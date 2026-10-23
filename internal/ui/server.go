// Package ui serves an authenticated control panel on one loopback address.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"exitguard/internal/model"
)

//go:embed assets/*
var assets embed.FS

const maxBody = 64 << 10

// Service is deliberately limited to core operations. In particular it cannot
// install OS filters or accept a caller's claim that protection is active.
type Service interface {
	Config() model.Config
	SaveConfig(model.Config) error
	Status() model.Status
	Check(context.Context) error
	ProbeCandidate(context.Context) (string, error)
	Arm(context.Context) error
	Disarm()
	SetSecret(string)
	Events() []model.Event
}

type Server struct {
	listener net.Listener
	http     *http.Server
	handler  *handler
}

type handler struct {
	service Service
	host    string
	token   string
	action  sync.Mutex
}

// New reserves an OS-selected loopback port and creates a new process token.
func New(service Service) (*Server, error) {
	if service == nil {
		return nil, errors.New("missing guard service")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	control, _, err := NewControl(service, listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	h := control.(*handler)
	return &Server{listener: listener, handler: h, http: &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10}}, nil
}

// NewControl embeds the panel in the guard-owned listener. Sharing its port
// keeps the control panel reachable by an explicitly protected browser without
// adding another destination to the OS filter's allow policy.
func NewControl(service Service, host string) (http.Handler, string, error) {
	address, port, err := net.SplitHostPort(host)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || address != "127.0.0.1" || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, "", errors.New("control host must be an explicit IPv4 loopback address")
	}
	if service == nil {
		return nil, "", errors.New("missing guard service")
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, "", err
	}
	h := &handler{service: service, host: host, token: base64.RawURLEncoding.EncodeToString(entropy[:])}
	return h, "http://" + host + "/#token=" + h.token, nil
}

// URL is a launch credential. Emit it only through the dedicated ready channel;
// do not put it in logs, errors, configuration, or command line arguments to core.
func (s *Server) URL() string { return "http://" + s.handler.host + "/#token=" + s.handler.token }

func (s *Server) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.http.Shutdown(shutdown)
		case <-done:
		}
	}()
	err := s.http.Serve(s.listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() error { return s.http.Close() }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if r.Host != h.host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+h.host) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		h.fail(w, http.StatusForbidden, "仅允许本机同源控制请求")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		want := "Bearer " + h.token
		got := r.Header.Get("Authorization")
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			h.fail(w, 401, "会话已失效，请重新打开应用")
			return
		}
		h.api(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		h.fail(w, 405, "不支持此操作")
		return
	}
	var file, contentType string
	switch r.URL.Path {
	case "/":
		file = "index.html"
		contentType = "text/html; charset=utf-8"
	case "/app.css":
		file = "app.css"
		contentType = "text/css; charset=utf-8"
	case "/app.js":
		file = "app.js"
		contentType = "application/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/" + file)
	if err != nil {
		h.fail(w, 500, "界面资源不可用")
		return
	}
	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func (h *handler) api(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/snapshot" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			h.fail(w, 405, "不支持此操作")
			return
		}
		h.snapshot(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		h.fail(w, 405, "不支持此操作")
		return
	}
	if contentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]); contentType != "application/json" {
		h.fail(w, 415, "需要 JSON 请求")
		return
	}
	// An explicit pause must be able to revoke a slow in-flight validation or
	// launch preparation; it cannot queue behind the ordinary action lock.
	if r.URL.Path == "/api/disarm" {
		if !h.decode(w, r, &struct{}{}) {
			return
		}
		h.service.Disarm()
		h.snapshot(w)
		return
	}
	if !h.action.TryLock() {
		h.fail(w, 409, "另一项操作正在进行")
		return
	}
	defer h.action.Unlock()
	switch r.URL.Path {
	case "/api/config":
		var config model.Config
		if !h.decode(w, r, &config) {
			return
		}
		if err := h.service.SaveConfig(config); err != nil {
			h.fail(w, 400, err.Error())
			return
		}
	case "/api/secret":
		var body struct {
			Secret string `json:"secret"`
		}
		if !h.decode(w, r, &body) {
			return
		}
		if len(body.Secret) > 4096 {
			h.fail(w, 400, "控制密钥过长")
			return
		}
		h.service.SetSecret(body.Secret)
	case "/api/candidate":
		if !h.decode(w, r, &struct{}{}) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		ip, err := h.service.ProbeCandidate(ctx)
		if err != nil {
			h.fail(w, 409, err.Error())
			return
		}
		h.json(w, 200, map[string]string{"candidateIP": ip, "message": "仅代表守护进程的候选出口，未保存为期望 IP，保护入口保持关闭"})
		return
	case "/api/check", "/api/arm":
		if !h.decode(w, r, &struct{}{}) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		var err error
		switch r.URL.Path {
		case "/api/check":
			err = h.service.Check(ctx)
		case "/api/arm":
			err = h.service.Arm(ctx)
		}
		if err != nil {
			h.fail(w, 409, err.Error())
			return
		}
	case "/api/launch":
		var body launchRequest
		if !h.decode(w, r, &body) {
			return
		}
		if h.service.Status().State != "armed" {
			h.fail(w, 409, "保护尚未启用，禁止启动受保护入口")
			return
		}
		var err error
		switch body.Kind {
		case "browser":
			err = launchBrowser(h.service, body)
		case "claude":
			err = launchClaude(h.service, body)
		default:
			err = errors.New("不支持此类程序启动")
		}
		if err != nil {
			h.fail(w, 409, err.Error())
			return
		}
	default:
		h.fail(w, 404, "未知操作")
		return
	}
	h.snapshot(w)
}

func (h *handler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		h.fail(w, 400, "无法读取请求")
		return false
	}
	if len(data) > maxBody {
		h.fail(w, 413, "请求超过大小限制")
		return false
	}
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "{") {
		h.fail(w, 400, "需要 JSON 对象")
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		h.fail(w, 400, "配置格式有误或包含不支持的字段")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		h.fail(w, 400, "每次只允许一个 JSON 对象")
		return false
	}
	return true
}

func (h *handler) snapshot(w http.ResponseWriter) {
	status := h.service.Status()
	h.json(w, 200, struct {
		Config      model.Config  `json:"config"`
		Status      model.Status  `json:"status"`
		Events      []model.Event `json:"events"`
		LaunchReady bool          `json:"launchReady"`
	}{h.service.Config(), status, h.service.Events(), status.State == "armed" && status.FilterActive})
}
func (h *handler) fail(w http.ResponseWriter, code int, message string) {
	h.json(w, code, map[string]string{"error": message})
}
func (h *handler) json(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		return
	}
}

// Ready is written exactly once on stdout for the native shell. The URL contains
// a bearer credential in its fragment, which is never sent in HTTP requests.
type Ready struct {
	Ready bool   `json:"ready"`
	URL   string `json:"url"`
}

func (s *Server) WriteReady(w io.Writer) error {
	if err := json.NewEncoder(w).Encode(Ready{true, s.URL()}); err != nil {
		return fmt.Errorf("write ready channel: %w", err)
	}
	return nil
}
