package guard

import (
	"bufio"
	"context"
	"exitguard/internal/enforce"
	"exitguard/internal/model"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type localRoute struct {
	testRoute
	target string
}

func (r *localRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", r.target)
}
func TestProxyDeniesBeforeArmAndClosesEstablishedTunnel(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "origin") }))
	defer origin.Close()
	s := configured(t)
	s.makeRoute = func(_ model.Config, _ string) (route, error) {
		return &localRoute{testRoute: testRoute{ip: "203.0.113.7"}, target: strings.TrimPrefix(origin.URL, "http://")}, nil
	}
	if res := proxyRaw(t, s, "CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n"); !strings.Contains(res, "503") {
		t.Fatalf("unarmed proxy %s", res)
	}
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	c, e := net.Dial("tcp", s.Status().ProxyAddress)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(c, "CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n")
	b := bufio.NewReader(c)
	resp, e := http.ReadResponse(b, &http.Request{Method: "CONNECT"})
	if e != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT %v %v", resp, e)
	}
	s.Disarm()
	if _, e = b.ReadByte(); e == nil {
		t.Fatal("existing tunnel survived Disarm")
	}
}
func TestHTTPProxyPreservesOriginRequest(t *testing.T) {
	var method, path, auth, body string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, auth = r.Method, r.RequestURI, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		fmt.Fprint(w, "origin-ok")
	}))
	defer origin.Close()
	s := configured(t)
	s.makeRoute = func(_ model.Config, _ string) (route, error) {
		return &localRoute{testRoute: testRoute{ip: "203.0.113.7"}, target: strings.TrimPrefix(origin.URL, "http://")}, nil
	}
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	res := proxyRaw(t, s, "POST http://origin.example/path?q=x HTTP/1.1\r\nHost: origin.example\r\nAuthorization: Bearer origin-secret\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
	if !strings.Contains(res, "origin-ok") || method != "POST" || path != "/path?q=x" || auth != "Bearer origin-secret" || body != "data" {
		t.Fatalf("origin request altered: %q %q %q %q %q", res, method, path, auth, body)
	}
}
func TestProxyRejectsMalformedOrOversizeRequests(t *testing.T) {
	s := configured(t)
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"CONNECT user@origin.example:443 HTTP/1.1\r\nHost: user@origin.example:443\r\n\r\n", "GET http://origin.example/ HTTP/1.1\r\nHost: origin.example\r\nX-Large: " + strings.Repeat("x", 70<<10) + "\r\n\r\n", "POST http://origin.example/ HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 9999999999\r\n\r\n"} {
		res := proxyRaw(t, s, raw)
		if strings.Contains(res, "200 Connection Established") {
			t.Fatal("invalid request admitted")
		}
		if !strings.Contains(res, "400") && !strings.Contains(res, "413") && !strings.Contains(res, "431") {
			t.Fatalf("invalid request was not rejected: %q", res)
		}
	}
}
func TestArmRequiresOwnedListener(t *testing.T) {
	s, e := New(filepath.Join(t.TempDir(), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveConfig(validConfig(t)); e != nil {
		t.Fatal(e)
	}
	s.inspect = func(_ context.Context, p enforce.Policy) (enforce.Proof, error) {
		return enforce.Proof{Active: true, PolicyHash: enforce.Hash(p)}, nil
	}
	s.makeRoute = func(model.Config, string) (route, error) { return &testRoute{ip: "203.0.113.7"}, nil }
	if e = s.Arm(context.Background()); e == nil {
		t.Fatal("armed without holding listener")
	}
}
func TestCandidateIPDoesNotArmOrOverwriteExpected(t *testing.T) {
	s := configured(t)
	c := s.Config()
	c.ExpectedIPs = nil
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	ip, e := s.ProbeCandidate(context.Background())
	if e != nil || ip != "203.0.113.7" {
		t.Fatalf("candidate %q %v", ip, e)
	}
	if s.Status().State == "armed" || s.Status().State == "ready" || len(s.Config().ExpectedIPs) != 0 {
		t.Fatal("candidate changed admission or expected IP")
	}
	if res := proxyRaw(t, s, "CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n"); !strings.Contains(res, "503") {
		t.Fatal("candidate opened proxy")
	}
}
func proxyRaw(t *testing.T, s *Service, raw string) string {
	t.Helper()
	c, e := net.Dial("tcp", s.Status().ProxyAddress)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = io.WriteString(c, raw); e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestOriginFormControlsAvailableWhileProxyGateClosed(t *testing.T) {
	s := configured(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh-test-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		fmt.Fprint(w, "trusted-local-control")
	}))
	host := s.Status().ProxyAddress
	res := proxyRaw(t, s, "GET /api/status HTTP/1.1\r\nHost: "+host+"\r\nAuthorization: Bearer fresh-test-token\r\nConnection: close\r\n\r\n")
	if !strings.Contains(res, "trusted-local-control") {
		t.Fatalf("closed proxy hid local controls: %s", res)
	}
	res = proxyRaw(t, s, "GET /api/status HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	if !strings.Contains(res, "401") {
		t.Fatal("unauthenticated local API bypass")
	}
	for _, raw := range []string{"GET /api/status HTTP/1.1\r\nHost: attacker.invalid\r\nAuthorization: Bearer fresh-test-token\r\n\r\n", "GET http://" + host + "/api/status HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer fresh-test-token\r\n\r\n", "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"} {
		if res = proxyRaw(t, s, raw); strings.Contains(res, "trusted-local-control") || strings.Contains(res, "200 Connection Established") {
			t.Fatal("forward-proxy/control dispatch bypass")
		}
	}
}

func TestHTTPProxyHandlesInformationalResponseBeforeBody(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(103); fmt.Fprint(w, "final-response-body") }))
	defer origin.Close()
	s := configured(t)
	s.makeRoute = func(_ model.Config, _ string) (route, error) {
		return &localRoute{testRoute: testRoute{ip: "203.0.113.7"}, target: strings.TrimPrefix(origin.URL, "http://")}, nil
	}
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	res := proxyRaw(t, s, "GET http://origin.example/path HTTP/1.1\r\nHost: origin.example\r\nConnection: close\r\n\r\n")
	if !strings.Contains(res, "final-response-body") {
		t.Fatalf("lost final response after informational headers: %q", res)
	}
}
