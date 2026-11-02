package guard

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type proxyConnectionKey struct{}

const maxProxyBody = 32 << 20

// Run owns only a loopback listener. It never changes system networking.
func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running || s.started {
		s.mu.Unlock()
		return errors.New("守护服务已在运行")
	}
	s.running = true
	s.started = true
	s.runContext = ctx
	c := s.config
	s.mu.Unlock()
	defer s.diagnostics.marker("process_stop")
	listener, e := net.Listen("tcp4", proxyAddress(c))
	if e != nil {
		s.mu.Lock()
		s.running = false
		close(s.readySignal)
		s.closeLocked()
		s.status.State = "blocked"
		s.status.Reason = "本地守护端口无法独占监听，请关闭冲突程序后重启"
		s.eventLocked(s.status.Reason)
		s.mu.Unlock()
		return errors.New("本地守护端口监听失败")
	}
	s.mu.Lock()
	s.listener = listener
	s.boundPort = c.ProxyPort
	close(s.readySignal)
	s.mu.Unlock()
	server := &http.Server{Handler: http.HandlerFunc(s.serveProxy), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 << 10, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, proxyConnectionKey{}, c)
	}, ConnState: func(c net.Conn, state http.ConnState) {
		s.mu.Lock()

		if state == http.StateClosed {
			delete(s.connections, c)
		}
		s.mu.Unlock()
	}}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	healthDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-healthDone:
				return
			case <-ticker.C:
				s.health(ctx)
			}
		}
	}()
	e = server.Serve(listener)
	close(done)
	close(healthDone)
	s.mu.Lock()
	s.running = false
	s.runContext = nil
	s.listener = nil
	s.boundPort = 0
	s.closeLocked()
	s.status.State = "stopped"
	s.status.Reason = "守护服务已停止，入口已关闭"
	s.eventLocked(s.status.Reason)
	s.mu.Unlock()
	if errors.Is(e, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return errors.New("守护代理监听已停止")
}
func (s *Service) serveProxy(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Connection", "close")
	s.mu.Lock()
	control, address := s.controlHandler, proxyAddress(s.config)
	s.mu.Unlock()
	if control != nil && req.Method != "CONNECT" && req.URL.Scheme == "" && req.URL.Host == "" && req.Host == address && strings.HasPrefix(req.RequestURI, "/") {
		control.ServeHTTP(w, req)
		return
	}
	r, g, open := s.admission()
	if !open {
		http.Error(w, "受保护入口尚未启用", http.StatusServiceUnavailable)
		return
	}
	if down, ok := req.Context().Value(proxyConnectionKey{}).(net.Conn); ok {
		if !s.track(down, g) {
			return
		}
	}
	var target string
	if req.Method == "CONNECT" {
		target = req.Host
		if req.URL.Host != "" && req.URL.Host != target {
			http.Error(w, "CONNECT 地址不一致", 400)
			return
		}
		if req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
			http.Error(w, "CONNECT 不允许请求体", 400)
			return
		}
	} else {
		if req.URL.Scheme != "http" || req.URL.Host == "" || req.URL.User != nil || req.URL.Fragment != "" || req.Header.Get("Upgrade") != "" {
			http.Error(w, "不支持此代理请求", 400)
			return
		}
		if !strings.EqualFold(req.Host, req.URL.Host) {
			http.Error(w, "目标主机不一致", 400)
			return
		}
		target = req.URL.Host
		if req.URL.Port() == "" {
			target = net.JoinHostPort(req.URL.Hostname(), "80")
		}
		if req.ContentLength > maxProxyBody {
			http.Error(w, "请求体过大", 413)
			return
		}
	}
	if _, _, e := targetAddress(target); e != nil {
		http.Error(w, "目标地址无效", 400)
		return
	}
	// Only connection setup is traced. Successful tunnels and target-local
	// refusals are discarded; no tunneled traffic is inspected or persisted.
	req = req.WithContext(s.startProbeTrace(req.Context(), diagnosticForward, g, 0, ""))
	if _, e := r.Fingerprint(req.Context()); e != nil {
		s.blockProxyFailure(req, g, "出口路径变化，入口已关闭", nil)
		return
	}
	upstream, e := r.DialContext(req.Context(), "tcp", target)
	if e != nil {
		if req.Context().Err() != nil {
			return
		}
		var unavailable *destinationError
		if errors.As(e, &unavailable) {
			s.noteProxyRequestFailure(req, g, unavailable.Error())
			http.Error(w, unavailable.Error(), http.StatusBadGateway)
			return
		}
		var classified *forwardError
		if errors.As(e, &classified) && classified.requestLocal() {
			s.noteProxyRequestFailure(req, g, classified.Error())
			http.Error(w, classified.Error(), classified.httpStatus())
			return
		}
		reason := "指定出口连接失败，入口已关闭"
		var failed *upstreamError
		if errors.As(e, &failed) {
			reason = failed.Error() + "，入口已关闭"
		} else if classified != nil {
			reason = classified.Error() + "，入口已关闭"
		}
		s.blockProxyFailure(req, g, reason, e)
		return
	}
	if !s.track(upstream, g) {
		http.Error(w, "出口验证已失效", 503)
		return
	}
	traceFrom(req.Context()).freeze(nil)
	defer s.untrack(upstream)
	// DialContext has now verified the route and completed upstream TLS/auth and
	// tunnel negotiation. Errors in the target exchange below affect only this
	// request; route identity and health failures retain their global checks.
	stopRequest := context.AfterFunc(req.Context(), func() { upstream.Close() })
	defer stopRequest()
	if req.Method == "CONNECT" {
		down, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		if !s.track(down, g) {
			return
		}
		defer s.untrack(down)
		if _, e = io.WriteString(b, "HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
			return
		}
		if e = b.Flush(); e != nil {
			return
		}
		copied := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, b); copied <- struct{}{} }()
		go func() { _, _ = io.Copy(down, upstream); copied <- struct{}{} }()
		<-copied
		return
	}
	outgoing := req.Clone(req.Context())
	outgoing.RequestURI = ""
	outgoing.URL.Scheme = ""
	outgoing.URL.Host = ""
	outgoing.Close = true
	outgoing.Header = outgoing.Header.Clone()
	removeHopHeaders(outgoing.Header)
	body := &proxyRequestBody{ReadCloser: http.MaxBytesReader(w, req.Body, maxProxyBody)}
	outgoing.Body = body
	if e = upstream.SetDeadline(time.Now().Add(60 * time.Second)); e != nil {
		s.failProxyRequest(w, req, g, e, "代理请求无法设置时限")
		return
	}
	if e = outgoing.Write(upstream); e != nil {
		// Request.Write may hide the body read error in a private http wrapper.
		if body.readErr != nil {
			e = body.readErr
		}
		s.failProxyRequest(w, req, g, e, "代理目标请求未完成")
		return
	}
	reader := bufio.NewReaderSize(upstream, 16<<10)
	var response *http.Response
	for informational := 0; informational < 9; informational++ {
		response, e = readResponseHead(reader, outgoing, 64<<10)
		if e != nil || response.StatusCode >= 200 || response.StatusCode == 101 {
			break
		}
		if informational == 8 {
			e = errors.New("过多中间响应")
		}
	}

	if e != nil {
		s.failProxyRequest(w, req, g, e, "代理目标响应无效")
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 101 {
		http.Error(w, "不支持 HTTP 升级，请使用 HTTPS CONNECT", 400)
		return
	}
	removeHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if _, e = io.Copy(w, response.Body); e != nil {
		_, reason := proxyExchangeFailure(e, "代理响应传输未完成")
		s.noteProxyRequestFailure(req, g, reason)
		// Headers may already be delivered. Abort this response so malformed or
		// incomplete origin bodies cannot be reported as a successful transfer.
		panic(http.ErrAbortHandler)
	}
}

type proxyRequestBody struct {
	io.ReadCloser
	readErr error
}

func (b *proxyRequestBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if e != nil && e != io.EOF {
		b.readErr = e
	}
	return n, e
}

func proxyExchangeFailure(e error, reason string) (int, string) {
	var limit *http.MaxBytesError
	if errors.As(e, &limit) {
		return http.StatusRequestEntityTooLarge, "请求体过大"
	}
	var timed net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &timed) && timed.Timeout() {
		return http.StatusGatewayTimeout, "代理请求超时"
	}
	return http.StatusBadGateway, reason
}

func (s *Service) noteProxyRequestFailure(req *http.Request, g uint64, reason string) {
	if req.Context().Err() != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation == g && activeState(s.status.State) {
		s.eventLocked(reason + "，仅拒绝此请求")
	}
}

func (s *Service) failProxyRequest(w http.ResponseWriter, req *http.Request, g uint64, e error, reason string) {
	if req.Context().Err() != nil {
		return
	}
	status, reason := proxyExchangeFailure(e, reason)
	s.noteProxyRequestFailure(req, g, reason)
	http.Error(w, reason, status)
}

func (s *Service) blockProxyFailure(req *http.Request, g uint64, reason string, cause error) {
	// A client abandoning one request says nothing about the verified route.
	// Upstream timeouts still block when this downstream request remains live.
	if req.Context().Err() == nil {
		s.mu.Lock()
		current := s.generation == g && activeState(s.status.State)
		s.mu.Unlock()
		if !current {
			return
		}
		failure := cause
		if failure == nil {
			failure = errRecoveryPath
		}
		reason += probeTraceSuffix(req.Context(), failure)
		defer s.finishProbeTrace(req.Context(), failure)
		origin := ""
		if trace := traceFrom(req.Context()); trace != nil {
			origin = trace.freeze(failure).CheckID
		}
		var classified *forwardError
		var upstream *upstreamError
		knownTransient := errors.As(cause, &classified) && classified.transient() || errors.As(cause, &upstream) && upstream.reason == "指定代理上游不可达"
		if knownTransient {
			s.mu.Lock()
			recovering := s.beginRecoveryLocked(g, reason, origin)
			s.mu.Unlock()
			if recovering {
				return
			}
		}
		_ = s.block(g, reason)
	}
}

func removeHopHeaders(h http.Header) {
	for _, key := range strings.Split(h.Get("Connection"), ",") {
		h.Del(strings.TrimSpace(key))
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}
