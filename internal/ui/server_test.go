package ui

import (
	"bufio"
	"context"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"exitguard/internal/guard"
	"exitguard/internal/model"
)

type testService struct {
	config                          model.Config
	status                          model.Status
	secret                          string
	proxyUsername, proxyPassword    string
	proxyCredentialError            error
	saved, checked, armed, disarmed int
}

func (s *testService) Config() model.Config { return s.config }
func (s *testService) Status() model.Status { return s.status }
func (s *testService) Events() []model.Event {
	return []model.Event{{Message: "<script>alert(1)</script>"}}
}
func (s *testService) SaveConfig(c model.Config) error {
	if len(c.ExpectedIPs) == 0 {
		return errors.New("expected IP required")
	}
	s.config = c
	s.saved++
	return nil
}
func (s *testService) Check(context.Context) error { s.checked++; return nil }
func (s *testService) Arm(context.Context) error   { s.armed++; return errors.New("filter unavailable") }
func (s *testService) Disarm()                     { s.disarmed++ }
func (s *testService) SetSecret(v string)          { s.secret = v }
func (s *testService) ProbeCandidate(context.Context) (string, error) {
	s.disarmed++
	s.status.State = "blocked"
	s.status.ObservedIP = "203.0.113.10"
	return s.status.ObservedIP, nil
}

func testHandler() (*handler, *testService) {
	s := &testService{status: model.Status{State: "unconfigured", Reason: "missing fixed IP", Platform: "darwin"}}
	return &handler{service: s, host: "127.0.0.1:12345", token: "test-token"}, s
}
func request(h http.Handler, method, path, body, token, host, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:12345"+path, strings.NewReader(body))
	r.Host = host
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestControlAuthenticationAndOrigin(t *testing.T) {
	h, _ := testHandler()
	for _, tc := range []struct {
		name, token, host, origin string
		want                      int
	}{
		{"missing token", "", "127.0.0.1:12345", "", 401},
		{"wrong token", "wrong", "127.0.0.1:12345", "", 401},
		{"foreign host", "test-token", "attacker.example:12345", "", 403},
		{"foreign origin", "test-token", "127.0.0.1:12345", "https://evil.example", 403},
		{"null origin", "test-token", "127.0.0.1:12345", "null", 403},
		{"different port", "test-token", "127.0.0.1:12345", "http://127.0.0.1:54321", 403},
		{"valid", "test-token", "127.0.0.1:12345", "http://127.0.0.1:12345", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(h, "GET", "/api/snapshot", "", tc.token, tc.host, tc.origin)
			if w.Code != tc.want {
				t.Fatalf("got %d: %s", w.Code, w.Body)
			}
		})
	}
}
func TestControlRequestBoundsAndClientFlags(t *testing.T) {
	h, s := testHandler()
	for _, body := range []string{`{"expectedIPs":["203.0.113.1"],"active":true}`, `{"expectedIPs":["203.0.113.1"],"filterActive":true}`, `{"expectedIPs":["203.0.113.1"],"secret":"never"}`, `{} {}`} {
		w := request(h, "POST", "/api/config", body, "test-token", h.host, "")
		if w.Code != 400 {
			t.Fatalf("unsafe config accepted: %d %s", w.Code, w.Body)
		}
	}
	w := request(h, "POST", "/api/config", strings.Repeat("x", maxBody+1), "test-token", h.host, "")
	if w.Code != 413 {
		t.Fatalf("oversize got %d", w.Code)
	}
	if s.saved != 0 {
		t.Fatal("invalid config reached save")
	}
	w = request(h, "POST", "/api/config", `{"expectedIPs":["203.0.113.1"]}`, "test-token", h.host, "")
	if w.Code != 200 || s.saved != 1 {
		t.Fatalf("valid config: %d %s", w.Code, w.Body)
	}
	w = request(h, "POST", "/api/config", `{}`, "test-token", h.host, "")
	if w.Code != 400 {
		t.Fatalf("validation ignored: %d", w.Code)
	}
}
func TestSecretIsSessionOnlyAndActionsCallService(t *testing.T) {
	h, s := testHandler()
	w := request(h, "POST", "/api/secret", `{"secret":"do-not-echo"}`, "test-token", h.host, "")
	if w.Code != 200 || s.secret != "do-not-echo" {
		t.Fatalf("secret: %d", w.Code)
	}
	w = request(h, "GET", "/api/snapshot", "", "test-token", h.host, "")
	if strings.Contains(w.Body.String(), "do-not-echo") || strings.Contains(w.Body.String(), "test-token") {
		t.Fatal("secret/token in response")
	}
	if !strings.Contains(w.Body.String(), "unconfigured") || !strings.Contains(w.Body.String(), "missing fixed IP") {
		t.Fatal("missing real readiness")
	}
	for _, endpoint := range []string{"check", "arm", "disarm"} {
		request(h, "POST", "/api/"+endpoint, `{}`, "test-token", h.host, "")
	}
	if s.checked != 1 || s.armed != 1 || s.disarmed != 1 {
		t.Fatal("actions did not reach core")
	}
	if s.status.State != "unconfigured" {
		t.Fatal("UI fabricated active state")
	}
}
func TestLaunchRefusesUnverifiedCoverageEvenWhenArmed(t *testing.T) {
	h, s := testHandler()
	for _, state := range []string{"unconfigured", "ready", "armed"} {
		s.status.State = state
		w := request(h, "POST", "/api/launch", `{"kind":"browser"}`, "test-token", h.host, "")
		if w.Code != 409 {
			t.Fatalf("unverified browser launched in %s: %d", state, w.Code)
		}
	}
}
func TestHTMLNoCredentialAndSecurityHeaders(t *testing.T) {
	h, _ := testHandler()
	w := request(h, "GET", "/", "", "", h.host, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ExitGuard") {
		t.Fatalf("panel: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "test-token") {
		t.Fatal("token embedded in HTML")
	}
	for _, header := range []string{"Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "Cache-Control"} {
		if w.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}
	w = request(h, "GET", "/api/arm", "", "test-token", h.host, "")
	if w.Code != 405 {
		t.Fatalf("GET arm: %d", w.Code)
	}
}

func TestBrowserCommandRequiresAcknowledgedConfiguredExecutableAndArmedFilter(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	path := filepath.Join(dir, "chrome.exe")
	if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
		t.Fatal(err)
	}
	c := model.Config{Programs: []string{path}, ProxyPort: 17890}
	s := model.Status{State: "armed", FilterActive: true, ProxyAddress: "127.0.0.1:17890"}
	r := launchRequest{Kind: "browser", Path: path, AcknowledgeProgramScope: true}
	cmd, err := browserCommand(c, s, r, "windows", filepath.Join(dir, "profile"))
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"--user-data-dir=", "--proxy-server=http://127.0.0.1:17890", "--proxy-bypass-list=<-loopback>;127.0.0.1:17890", "--disable-quic", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %s in %s", want, args)
		}
	}
	if strings.Contains(strings.ToUpper(args), "DIRECT") {
		t.Fatal("direct fallback configured")
	}
	r.AcknowledgeProgramScope = false
	if _, err := browserCommand(c, s, r, "windows", dir); err == nil {
		t.Fatal("scope acknowledgement ignored")
	}
	r.AcknowledgeProgramScope = true
	c.Programs = nil
	if _, err := browserCommand(c, s, r, "windows", dir); err == nil {
		t.Fatal("unlisted executable allowed")
	}
	c.Programs = []string{path}
	s.FilterActive = false
	if _, err := browserCommand(c, s, r, "windows", dir); err == nil {
		t.Fatal("armed state alone allowed launch")
	}
}

func TestMacBrowserRequiresEveryPackagedHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS launch fixture requires POSIX executable permission bits; Mach-O parser has separate portable coverage")
	}
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	app := filepath.Join(dir, "Google Chrome.app")
	main := filepath.Join(app, "Contents", "MacOS", "Google Chrome")
	helper := filepath.Join(app, "Contents", "Frameworks", "Google Chrome Framework.framework", "Versions", "1", "Helpers", "Google Chrome Helper.app", "Contents", "MacOS", "Google Chrome Helper")
	for _, path := range []string{main, helper} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, machOFixture(macho.TypeExec), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := model.Config{Programs: []string{main}, ProxyPort: 17890}
	s := model.Status{State: "armed", FilterActive: true, ProxyAddress: "127.0.0.1:17890"}
	r := launchRequest{Kind: "browser", Path: main, AcknowledgeProgramScope: true}
	if _, err := browserCommand(c, s, r, "darwin", filepath.Join(dir, "profile")); err == nil {
		t.Fatal("missing helper coverage allowed")
	}
	c.Programs = append(c.Programs, helper)
	if _, err := browserCommand(c, s, r, "darwin", filepath.Join(dir, "profile")); err != nil {
		t.Fatalf("complete helper paths rejected: %v", err)
	}
}

func machOFixture(kind macho.Type) []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(data[12:16], uint32(kind))
	return data
}

func TestMachOExecutableKindsPortable(t *testing.T) {
	fat := make([]byte, 64)
	binary.BigEndian.PutUint32(fat[0:4], macho.MagicFat)
	binary.BigEndian.PutUint32(fat[4:8], 1)
	binary.BigEndian.PutUint32(fat[8:12], uint32(macho.CpuArm64))
	binary.BigEndian.PutUint32(fat[16:20], 32)
	binary.BigEndian.PutUint32(fat[20:24], 32)
	copy(fat[32:], machOFixture(macho.TypeExec))
	for _, tc := range []struct {
		name                string
		data                []byte
		executable, wantErr bool
	}{
		{"thin executable", machOFixture(macho.TypeExec), true, false},
		{"thin dynamic library", machOFixture(macho.TypeDylib), false, false},
		{"fat executable", fat, true, false},
		{"ordinary resource", []byte("plain-text resource"), false, false},
		{"invalid known Mach-O", machOFixture(macho.TypeExec)[:8], false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := isMachOExecutable(path)
			if (err != nil) != tc.wantErr || got != tc.executable {
				t.Fatalf("got executable=%v error=%v", got, err)
			}
		})
	}
}

func TestMacBrowserRequiresMachOHelpersOutsideAppFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS launch fixture requires POSIX executable permission bits; Mach-O parser has separate portable coverage")
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	app := filepath.Join(dir, "Google Chrome.app")
	main := filepath.Join(app, "Contents", "MacOS", "Google Chrome")
	helper := filepath.Join(app, "Contents", "Frameworks", "Google Chrome Helper.app", "Contents", "MacOS", "Google Chrome Helper")
	crashpad := filepath.Join(app, "Contents", "Frameworks", "Google Chrome Framework.framework", "Versions", "1", "Helpers", "chrome_crashpad_handler")
	dylib := filepath.Join(app, "Contents", "Frameworks", "Google Chrome Framework.framework", "Versions", "1", "Google Chrome Framework")
	for _, path := range []string{main, helper, crashpad, dylib} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		kind := macho.TypeExec
		if path == dylib {
			kind = macho.TypeDylib
		}
		if err := os.WriteFile(path, machOFixture(kind), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := model.Config{Programs: []string{main, helper}, ProxyPort: 17890}
	s := model.Status{State: "armed", FilterActive: true, ProxyAddress: "127.0.0.1:17890"}
	r := launchRequest{Kind: "browser", Path: main, AcknowledgeProgramScope: true}
	if _, err := browserCommand(c, s, r, "darwin", filepath.Join(dir, "profile")); err == nil {
		t.Fatal("standalone Mach-O crashpad helper escaped declared coverage")
	}
	c.Programs = append(c.Programs, crashpad)
	if _, err := browserCommand(c, s, r, "darwin", filepath.Join(dir, "profile")); err != nil {
		t.Fatalf("dylib must not require executable filtering: %v", err)
	}
}

func TestCandidateDoesNotEnableProtectionOrWriteExpectedIP(t *testing.T) {
	h, s := testHandler()
	w := request(h, "POST", "/api/candidate", `{}`, "test-token", h.host, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "203.0.113.10") {
		t.Fatalf("candidate: %d %s", w.Code, w.Body)
	}
	if s.status.State != "blocked" || s.armed != 0 || len(s.config.ExpectedIPs) != 0 {
		t.Fatal("candidate became trusted protection")
	}
}

func TestControlRejectsNullBodiesAndInvalidHosts(t *testing.T) {
	h, _ := testHandler()
	w := request(h, "POST", "/api/config", `null`, "test-token", h.host, "")
	if w.Code != 400 {
		t.Fatalf("null body: %d", w.Code)
	}
	for _, host := range []string{"localhost:17890", "127.0.0.1:0", "127.0.0.1:999999", "127.0.0.1:abc", "0.0.0.0:17890"} {
		if _, _, err := NewControl(h.service, host); err == nil {
			t.Fatalf("unsafe host accepted: %s", host)
		}
	}
}

func TestClaudeCommandIsConfiguredAndUsesExplicitProxy(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	path := filepath.Join(dir, "Claude.exe")
	if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
		t.Fatal(err)
	}
	c := model.Config{Programs: []string{path}, ProxyPort: 17890}
	s := model.Status{State: "armed", FilterActive: true, ProxyAddress: "127.0.0.1:17890"}
	r := launchRequest{Kind: "claude", Path: path, AcknowledgeProgramScope: true}
	cmd, err := claudeCommand(c, s, r, "windows")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "--proxy-server=http://127.0.0.1:17890") || !strings.Contains(args, "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1") || strings.Contains(strings.ToUpper(args), "DIRECT") {
		t.Fatalf("invalid client flags: %s", args)
	}
	c.Programs = nil
	if _, err := claudeCommand(c, s, r, "windows"); err == nil {
		t.Fatal("unconfigured Claude allowed")
	}
}

func TestTaskListRecognizesExistingClaudeWithoutKillingIt(t *testing.T) {
	for _, tc := range []struct {
		data string
		want bool
	}{
		{"\"Claude.exe\",\"123\",\"Console\",\"1\",\"200 K\"\r\n", true},
		{"\"claude.EXE\",\"123\",\"Console\",\"1\",\"200 K\"\r\n", true},
		{"INFO: No tasks are running which match the specified criteria.\r\n", false},
		{"\"chrome.exe\",\"123\",\"Console\",\"1\",\"200 K\"\r\n", false},
	} {
		if got := taskListHasImage([]byte(tc.data), "Claude.exe"); got != tc.want {
			t.Fatalf("got %v for %s", got, tc.data)
		}
	}
}

func TestSharedListenerControlCannotOpenUnconfiguredProxy(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(model.Config{Mode: "feilian", ProxyPort: port})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	service, err := guard.New(path)
	if err != nil {
		t.Fatal(err)
	}
	h, launchURL, err := NewControl(service, service.Status().ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetControlHandler(h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	if err := service.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	base := "http://" + service.Status().ProxyAddress
	token := strings.Split(launchURL, "#token=")[1]
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	for _, tc := range []struct {
		path, method, body, token string
		want                      int
	}{
		{"/", "GET", "", "", 200},
		{"/api/snapshot", "GET", "", "", 401},
		{"/api/snapshot", "GET", "", token, 200},
		{"/api/arm", "POST", `{"filterActive":true}`, token, 400},
		{"/api/launch", "POST", `{"kind":"browser"}`, token, 409},
	} {
		r, _ := http.NewRequest(tc.method, base+tc.path, strings.NewReader(tc.body))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		if tc.method == "POST" {
			r.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatalf("%s: %d", tc.path, response.StatusCode)
		}
	}
	if service.Status().State == "armed" {
		t.Fatal("control request bypassed readiness")
	}
	// Absolute-form proxy requests must never be mistaken for origin-form
	// control requests, even with the correct API credential and destination.
	conn, err := net.Dial("tcp4", service.Status().ProxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(conn, "GET "+base+"/api/snapshot HTTP/1.1\r\nHost: "+service.Status().ProxyAddress+"\r\nAuthorization: Bearer "+token+"\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == 200 {
		t.Fatal("absolute-form request reached control handler")
	}
}

type blockingService struct {
	testService
	entered, release, stopped chan struct{}
}

func (s *blockingService) Check(ctx context.Context) error {
	close(s.entered)
	select {
	case <-s.release:
		return errors.New("cancelled check")
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *blockingService) Disarm() { close(s.stopped) }

func TestDisarmDoesNotWaitForLongControlOperation(t *testing.T) {
	s := &blockingService{entered: make(chan struct{}), release: make(chan struct{}), stopped: make(chan struct{})}
	h := &handler{service: s, host: "127.0.0.1:12345", token: "test-token"}
	checkDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { checkDone <- request(h, "POST", "/api/check", `{}`, "test-token", h.host, "") }()
	<-s.entered
	defer func() { close(s.release); <-checkDone }()
	stopDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { stopDone <- request(h, "POST", "/api/disarm", `{}`, "test-token", h.host, "") }()
	select {
	case result := <-stopDone:
		if result.Code != 200 {
			t.Fatalf("pause during check: %d", result.Code)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pause queued behind long operation")
	}
	select {
	case <-s.stopped:
	default:
		t.Fatal("core Disarm was not called")
	}
}

func TestFinalProcessStartRechecksCurrentProtection(t *testing.T) {
	expected := model.Status{State: "armed", FilterActive: true, PolicyHash: "policy-1", ProxyAddress: "127.0.0.1:17890"}
	s := &testService{status: expected}
	s.status.State = "stopped"
	command := exec.Command(os.Args[0], "-test.run=^$")
	if err := startIfArmed(s, expected, command); err == nil {
		t.Fatal("stale launch started after pause")
	}
	if command.Process != nil {
		t.Fatal("process created after protection was revoked")
	}
}

func (s *testService) SetProxyCredentials(username, password string) error {
	s.proxyUsername, s.proxyPassword = username, password
	return s.proxyCredentialError
}

func TestProxyCredentialsUseAuthenticatedBoundedAPIWithoutEcho(t *testing.T) {
	h, s := testHandler()
	body := `{"username":"session-user","password":"session-password"}`
	w := request(h, "POST", "/api/proxy-credentials", body, "", h.host, "")
	if w.Code != 401 || s.proxyUsername != "" {
		t.Fatal("unauthenticated credentials accepted")
	}
	w = request(h, "POST", "/api/proxy-credentials", body, "test-token", h.host, "")
	if w.Code != 200 || s.proxyUsername != "session-user" || s.proxyPassword != "session-password" {
		t.Fatalf("credential submission: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/api/snapshot", "/api/proxy-credentials"} {
		method, payload := "GET", ""
		if path != "/api/snapshot" {
			method, payload = "POST", body
		}
		w = request(h, method, path, payload, "test-token", h.host, "")
		if strings.Contains(w.Body.String(), "session-user") || strings.Contains(w.Body.String(), "session-password") {
			t.Fatal("credential echoed")
		}
	}
	s.proxyCredentialError = errors.New("invalid session-password")
	w = request(h, "POST", "/api/proxy-credentials", body, "test-token", h.host, "")
	if w.Code != 400 || strings.Contains(w.Body.String(), "session-password") {
		t.Fatal("credential validation failed to redact error")
	}
	for _, body := range []string{`{"username":"u","password":"p","url":"http://evil"}`, `{"username":"` + strings.Repeat("u", 4097) + `","password":"p"}`} {
		w = request(h, "POST", "/api/proxy-credentials", body, "test-token", h.host, "")
		if w.Code != 400 {
			t.Fatalf("invalid credentials: %d", w.Code)
		}
	}
}

func proxyOnlyFixture(t *testing.T) (model.Config, model.Status) {
	t.Helper()
	var c model.Config
	var s model.Status
	if err := json.Unmarshal([]byte(`{"enforcementMode":"proxy-only","proxyPort":17890}`), &c); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"enforcementMode":"proxy-only","state":"proxy_active","filterActive":false,"proxyAddress":"127.0.0.1:17890","sessionRevision":8}`), &s); err != nil {
		t.Fatal(err)
	}
	return c, s
}

func TestProxyOnlyBrowserAndClaudeLaunchWithoutOSCoverage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS launch fixture requires POSIX executable permission bits; Mach-O parser has separate portable coverage")
	}
	c, s := proxyOnlyFixture(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	for _, target := range []struct{ kind, name string }{{"browser", "Google Chrome"}, {"claude", "Claude"}} {
		path := filepath.Join(dir, target.name)
		if err := os.WriteFile(path, []byte("fixture executable"), 0700); err != nil {
			t.Fatal(err)
		}
		r := launchRequest{Kind: target.kind, Path: path}
		var cmd *exec.Cmd
		var err error
		if target.kind == "browser" {
			cmd, err = browserCommand(c, s, r, "darwin", filepath.Join(dir, "profile"))
		} else {
			cmd, err = claudeCommand(c, s, r, "darwin")
		}
		if err != nil {
			t.Fatalf("%s proxy-only launch requires strict OS proof: %v", target.kind, err)
		}
		args := strings.Join(cmd.Args, " ")
		if !strings.Contains(args, "--proxy-server=http://127.0.0.1:17890") || strings.Contains(strings.ToUpper(args), "DIRECT") {
			t.Fatalf("unsafe arguments: %s", args)
		}
	}
}

func TestLaunchReadinessRejectsModeStateMismatch(t *testing.T) {
	h, service := testHandler()
	service.config, service.status = proxyOnlyFixture(t)
	w := request(h, "GET", "/api/snapshot", "", "test-token", h.host, "")
	if !strings.Contains(w.Body.String(), `"launchReady":true`) {
		t.Fatalf("proxy-active not launchable: %s", w.Body)
	}
	for _, statusJSON := range []string{
		`{"enforcementMode":"required","state":"proxy_active","filterActive":false}`,
		`{"enforcementMode":"proxy-only","state":"armed","filterActive":true}`,
		`{"enforcementMode":"proxy-only","state":"proxy_active","filterActive":true}`,
		`{"enforcementMode":"proxy-only","state":"proxy_ready","filterActive":false}`,
	} {
		json.Unmarshal([]byte(statusJSON), &service.status)
		w = request(h, "GET", "/api/snapshot", "", "test-token", h.host, "")
		if !strings.Contains(w.Body.String(), `"launchReady":false`) {
			t.Fatalf("mismatched status launchable: %s", w.Body)
		}
	}
}

func TestFinalProcessStartRejectsReactivatedSessionRevision(t *testing.T) {
	for _, strict := range []bool{false, true} {
		c, expected := proxyOnlyFixture(t)
		if strict {
			c.EnforcementMode = "required"
			expected.EnforcementMode, expected.State, expected.FilterActive = "required", "armed", true
			expected.PolicyHash = "same-policy"
		}
		current := expected
		current.SessionRevision++
		s := &testService{config: c, status: current}
		command := exec.Command(os.Args[0], "-test.run=^$")
		err := startIfArmed(s, expected, command)
		if command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if err == nil || command.Process != nil {
			t.Fatalf("stale activation revision started a process (strict=%v)", strict)
		}
	}
}

func TestLaunchAPIRejectsCachedProxySessionRevision(t *testing.T) {
	h, s := testHandler()
	s.config, s.status = proxyOnlyFixture(t)
	w := request(h, "POST", "/api/launch", `{"kind":"browser","path":"/not-started","sessionRevision":7}`, "test-token", h.host, "")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "会话已变化") {
		t.Fatalf("stale revision was not rejected before launch: %d %s", w.Code, w.Body)
	}
	w = request(h, "POST", "/api/launch", `{"kind":"browser","path":"/not-started"}`, "test-token", h.host, "")
	if w.Code != 409 || !strings.Contains(w.Body.String(), "会话已变化") {
		t.Fatalf("proxy launch omitted revision: %d %s", w.Code, w.Body)
	}
}

func TestProxyLaunchCommandRejectsRequestRevisionChangedDuringPreparation(t *testing.T) {
	c, s := proxyOnlyFixture(t)
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(dir, "chrome.exe")
	if err := os.WriteFile(path, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	stale := uint64(7)
	r := launchRequest{Kind: "browser", Path: path, SessionRevision: &stale}
	if _, err := browserCommand(c, s, r, "windows", filepath.Join(dir, "profile")); err == nil {
		t.Fatal("old UI session accepted during command preparation")
	}
}
