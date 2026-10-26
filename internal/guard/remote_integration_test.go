package guard

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"exitguard/internal/enforce"
	"exitguard/internal/model"
)

// This integration uses real TLS, DoH, upstream CONNECT and localhost forwarding.
// The fixture maps documentation-only destination IPv4s to its own local origins.
// OS proof is explicitly unavailable: successful activation proves proxy-only
// forwarding works without faking the condition required by strict mode.
func TestRemoteProxyOnlyRealForwardingWithoutOSProof(t *testing.T) {
	var leaked atomic.Bool
	originHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || strings.Contains(r.Header.Get("Authorization"), "fixture-password") {
			leaked.Store(true)
		}
		if r.URL.Path == "/ip" {
			fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
			return
		}
		if r.Method != "POST" || r.URL.RequestURI() != "/payload?q=1" || r.Header.Get("Authorization") != "Bearer origin-token" {
			http.Error(w, "origin request changed", 400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "origin:%s", body)
	})
	plain := httptest.NewServer(originHandler)
	defer plain.Close()
	secure := httptest.NewTLSServer(originHandler)
	defer secure.Close()
	var queries atomic.Int32
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			leaked.Store(true)
		}
		q, _ := io.ReadAll(r.Body)
		name, end, e := dnsName(q, 12)
		if e != nil || name != "example.com" || binary.BigEndian.Uint16(q[end:end+2]) != 1 {
			http.Error(w, "unexpected DNS question", 400)
			return
		}
		queries.Add(1)
		answer := append([]byte(nil), q...)
		binary.BigEndian.PutUint16(answer[2:4], 0x8180)
		binary.BigEndian.PutUint16(answer[6:8], 1)
		answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 70)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer)
	}))
	defer doh.Close()
	portOf := func(raw string) string { u, _ := url.Parse(raw); return u.Port() }
	destinations := map[string]string{
		net.JoinHostPort("203.0.113.53", portOf(doh.URL)):    strings.TrimPrefix(doh.URL, "https://"),
		net.JoinHostPort("203.0.113.70", portOf(secure.URL)): strings.TrimPrefix(secure.URL, "https://"),
		net.JoinHostPort("203.0.113.70", portOf(plain.URL)):  strings.TrimPrefix(plain.URL, "http://"),
	}
	var hitsMu sync.Mutex
	var hits []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password")) {
			w.WriteHeader(407)
			return
		}
		hitsMu.Lock()
		hits = append(hits, r.Host)
		hitsMu.Unlock()
		address, exists := destinations[r.Host]
		if !exists {
			w.WriteHeader(403)
			return
		}
		up, e := net.DialTimeout("tcp4", address, time.Second)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer up.Close()
		down, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer down.Close()
		fmt.Fprint(b, "HTTP/1.1 200 Connection Established\r\n\r\n")
		b.Flush()
		done := make(chan struct{}, 2)
		go func() { io.Copy(up, b); done <- struct{}{} }()
		go func() { io.Copy(down, up); done <- struct{}{} }()
		<-done
	}))
	defer upstream.Close()

	s, e := New(filepath.Join(t.TempDir(), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	c := remoteConfig(upstream.URL)
	c.ProxyPort, c.ExpectedIPs = port, []string{"203.0.113.7"}
	c.ProbeURL = "https://example.com:" + portOf(secure.URL) + "/ip"
	c.DNSResolverURL, c.DNSBootstrapIP = "https://example.com:"+portOf(doh.URL)+"/dns-query", "203.0.113.53"
	if e = s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	if e = s.SetProxyCredentials("fixture-user", "fixture-password"); e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(secure.Certificate())
	roots.AddCert(doh.Certificate())
	s.makeRemoteRoute = func(ctx context.Context, c model.Config, user, password string) (route, error) {
		return newRemoteRouteWithDependencies(ctx, c, user, password, remoteDependencies{roots: roots})
	}
	s.inspect = func(context.Context, enforce.Policy) (enforce.Proof, error) {
		t.Error("proxy-only requested OS proof")
		return enforce.Proof{}, errors.New("no OS enforcement installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if e = s.WaitReady(waitCtx); e != nil {
		t.Fatal(e)
	}
	if e = s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	if st := s.Status(); st.State != "proxy_active" || st.FilterActive || st.PolicyHash != "" || st.SessionRevision == 0 {
		t.Fatalf("invalid ordinary proxy activation: %+v", st)
	}
	proxyURL, _ := url.Parse("http://" + s.Status().ProxyAddress)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for _, scheme := range []string{"http", "https"} {
		port := portOf(plain.URL)
		if scheme == "https" {
			port = portOf(secure.URL)
		}
		req, _ := http.NewRequest("POST", scheme+"://example.com:"+port+"/payload?q=1", strings.NewReader("forwarded-body"))
		req.Header.Set("Authorization", "Bearer origin-token")
		if scheme == "http" {
			req.Header.Set("Proxy-Authorization", "Basic client-must-not-reach-origin")
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatalf("%s through real local proxy: %v", scheme, e)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "origin:forwarded-body" {
			t.Fatalf("%s forwarding: %d %q", scheme, resp.StatusCode, body)
		}
	}
	if leaked.Load() || queries.Load() < 3 {
		t.Fatalf("credentials reached origins or same-upstream DoH unused: leaked=%v queries=%d", leaked.Load(), queries.Load())
	}
	hitsMu.Lock()
	if len(hits) < 6 {
		t.Errorf("missing upstream paths: %v", hits)
	}
	for _, dest := range hits {
		if strings.Contains(dest, "example.com") {
			t.Errorf("target name leaked to proxy instead of same-route DoH IPv4: %s", dest)
		}
	}
	hitsMu.Unlock()
	// A live opaque tunnel is owned by the service and closes immediately on pause.
	tunnel, e := net.Dial("tcp4", s.Status().ProxyAddress)
	if e != nil {
		t.Fatal(e)
	}
	defer tunnel.Close()
	tunnel.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(tunnel, "CONNECT example.com:%s HTTP/1.1\r\nHost: example.com:%s\r\n\r\n", portOf(secure.URL), portOf(secure.URL))
	reader := bufio.NewReader(tunnel)
	response, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || response.StatusCode != 200 {
		t.Fatalf("opaque tunnel not established: %v %v", response, e)
	}
	revision := s.Status().SessionRevision
	s.Disarm()
	if _, e = reader.ReadByte(); e == nil {
		t.Fatal("live proxy-only tunnel survived pause")
	}
	if st := s.Status(); st.SessionRevision == revision || st.State != "stopped" || st.FilterActive {
		t.Fatalf("pause not revoked: %+v", st)
	}
	// Closed upstream must fail through the configured route and revoke admission.
	if e = s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	upstream.Close()
	if resp, e := client.Get("http://example.com:" + portOf(plain.URL) + "/payload"); e == nil {
		resp.Body.Close()
		t.Fatal("closed upstream unexpectedly reached target")
	}
	if st := s.Status(); st.State != "blocked" {
		t.Fatalf("upstream failure did not close entry: %+v", st)
	}
	all, _ := json.Marshal([]any{s.Config(), s.Status(), s.Events()})
	if strings.Contains(string(all), "fixture-user") || strings.Contains(string(all), "fixture-password") {
		t.Fatal("credentials leaked to service output")
	}
}
