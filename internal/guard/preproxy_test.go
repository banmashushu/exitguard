package guard

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"exitguard/internal/model"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The front fixture only accepts the final endpoint and its own account. Any
// direct final dial, business target at hop one or crossed account fails.
func frontProxyFixture(t *testing.T, scheme, target, behavior string, hits *atomic.Int32, failNext ...*atomic.Bool) (string, *x509.Certificate) {
	t.Helper()
	relay := func(down net.Conn, reader io.Reader) {
		defer down.Close()
		hits.Add(1)
		if behavior == "stall" {
			io.Copy(io.Discard, down)
			return
		}
		up, err := net.DialTimeout("tcp4", target, time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(up, reader); done <- struct{}{} }()
		go func() { io.Copy(down, up); done <- struct{}{} }()
		<-done
	}
	if scheme != "socks5" {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" || r.Host != target || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("front-user:front-password")) {
				w.WriteHeader(407)
				return
			}
			if behavior == "deny" {
				hits.Add(1)
				w.WriteHeader(403)
				return
			}
			c, b, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			if behavior == "early-close" || len(failNext) > 0 && failNext[0].Swap(false) {
				hits.Add(1)
				c.Close()
				return
			}
			if behavior == "malformed" {
				hits.Add(1)
				io.WriteString(c, "HTTP/1.1 nonsense\r\n\r\n")
				c.Close()
				return
			}
			if behavior != "stall" {
				fmt.Fprint(b, "HTTP/1.1 200 Tunnel\r\n\r\n")
				b.Flush()
			}
			relay(c, b)
		})
		srv := httptest.NewUnstartedServer(h)
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		if scheme == "https" {
			srv.StartTLS()
		} else {
			srv.Start()
		}
		t.Cleanup(srv.Close)
		if scheme == "https" {
			return srv.URL, srv.Certificate()
		}
		return srv.URL, nil
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var h [2]byte
				if _, err := io.ReadFull(c, h[:]); err != nil || h != [2]byte{5, 1} {
					return
				}
				var method [1]byte
				io.ReadFull(c, method[:])
				if method[0] != 2 {
					return
				}
				c.Write([]byte{5, 2})
				io.ReadFull(c, h[:])
				u := make([]byte, int(h[1]))
				io.ReadFull(c, u)
				io.ReadFull(c, method[:])
				p := make([]byte, int(method[0]))
				io.ReadFull(c, p)
				if string(u) != "front-user" || string(p) != "front-password" {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				var request [10]byte
				if _, err := io.ReadFull(c, request[:]); err != nil || request[3] != 1 {
					return
				}
				got := net.JoinHostPort(net.IP(request[4:8]).String(), fmt.Sprint(binary.BigEndian.Uint16(request[8:])))
				if got != target {
					return
				}
				if behavior == "deny" {
					hits.Add(1)
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				if behavior != "stall" {
					c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				}
				relay(c, c)
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-acceptDone; wg.Wait() })
	return "socks5://" + l.Addr().String(), nil
}

func TestPreProxyAllProtocolsAuthenticateOnlyTheirHop(t *testing.T) {
	for _, frontScheme := range []string{"http", "https", "socks5"} {
		for _, finalScheme := range []string{"http", "https", "socks5"} {
			t.Run(frontScheme+"-"+finalScheme, func(t *testing.T) {
				roots := x509.NewCertPool()
				var endpoint string
				if finalScheme == "socks5" {
					endpoint = socksFixture(t, "success")
				} else {
					srv := echoHTTPFixture(t, finalScheme == "https")
					defer srv.Close()
					endpoint = srv.URL
					if finalScheme == "https" {
						roots.AddCert(srv.Certificate())
					}
				}
				u, _ := url.Parse(endpoint)
				var hits atomic.Int32
				front, cert := frontProxyFixture(t, frontScheme, u.Host, "", &hits)
				if cert != nil {
					roots.AddCert(cert)
				}
				cfg := remoteConfig(endpoint)
				cfg.PreProxyURL = front
				r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "fixture-user", "fixture-password", "front-user", "front-password", remoteDependencies{roots: roots})
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				assertRemoteEcho(t, r)
				fp, _ := r.Fingerprint(context.Background())
				if !strings.Contains(fp, "preproxy:") || hits.Load() != 1 {
					t.Fatal("chain identity or first hop missing")
				}
			})
		}
	}
}

func TestPreProxyFailureNeverDialsFinalOrBecomesBusinessLocal(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			var finalHits atomic.Int32
			final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { finalHits.Add(1); w.WriteHeader(200) }))
			defer final.Close()
			u, _ := url.Parse(final.URL)
			var hits atomic.Int32
			front, _ := frontProxyFixture(t, scheme, u.Host, "deny", &hits)
			cfg := remoteConfig(final.URL)
			cfg.PreProxyURL = front
			r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "", "", "front-user", "front-password", remoteDependencies{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			c, err := r.DialContext(context.Background(), "tcp", "203.0.113.70:443")
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("first-hop refusal admitted")
			}
			var local *destinationError
			if errors.As(err, &local) {
				t.Fatal("first-hop refusal became request-local")
			}
			if finalHits.Load() != 0 || hits.Load() != 1 {
				t.Fatal("route bypassed first hop")
			}
		})
	}
}

func TestPreProxyPinningIdentitySelfLoopsAndCancellation(t *testing.T) {
	final := echoHTTPFixture(t, false)
	defer final.Close()
	u, _ := url.Parse(final.URL)
	var hits atomic.Int32
	front, _ := frontProxyFixture(t, "http", u.Host, "stall", &hits)
	fu, _ := url.Parse(front)
	cfg := remoteConfig("http://final-private.example:" + u.Port())
	cfg.PreProxyURL = "http://front-private.example:" + fu.Port()
	var lookups atomic.Int32
	r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "fixture-user", "fixture-password", "front-user", "front-password", remoteDependencies{lookupIP: func(context.Context, string, string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		c, err := r.DialContext(ctx, "tcp", "203.0.113.70:443")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel admitted")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("first-hop cancellation stuck")
	}
	if lookups.Load() != 2 {
		t.Fatal("proxy endpoints were not each pinned once")
	}
	for _, front := range []string{final.URL, "http://127.0.0.1:17890", "http://localhost:17890"} {
		cfg := remoteConfig(final.URL)
		cfg.PreProxyURL = front
		r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "", "", "", "", remoteDependencies{})
		if err == nil {
			r.Close()
			t.Fatal("self-loop accepted")
		}
	}
}

func TestPreProxyTransportFailureKeepsAttributionThroughDoH(t *testing.T) {
	final := echoHTTPFixture(t, false)
	defer final.Close()
	u, _ := url.Parse(final.URL)
	var hits atomic.Int32
	front, _ := frontProxyFixture(t, "http", u.Host, "early-close", &hits)
	cfg := remoteConfig(final.URL)
	cfg.PreProxyURL = front
	r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "fixture-user", "fixture-password", "front-user", "front-password", remoteDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	connection, err := r.DialContext(context.Background(), "tcp", "business-private.example:443")
	if connection != nil {
		connection.Close()
	}
	var first *preProxyError
	if err == nil || !errors.As(err, &first) || !transientRecoveryFailure(err) || !strings.Contains(err.Error(), "前置代理") {
		t.Fatalf("DoH erased first-hop failure or recovery classification: %v", err)
	}
}

func TestPreProxyAuthenticationTLSAndProtocolFailuresStayHard(t *testing.T) {
	for _, failure := range []string{"front-auth", "front-tls", "front-protocol", "final-auth", "final-tls"} {
		t.Run(failure, func(t *testing.T) {
			roots := x509.NewCertPool()
			finalSecure := failure == "final-tls"
			final := echoHTTPFixture(t, finalSecure)
			defer final.Close()
			u, _ := url.Parse(final.URL)
			var hits atomic.Int32
			scheme, behavior := "http", ""
			if failure == "front-tls" {
				scheme = "https"
			}
			if failure == "front-protocol" {
				behavior = "malformed"
			}
			front, _ := frontProxyFixture(t, scheme, u.Host, behavior, &hits)
			cfg := remoteConfig(final.URL)
			cfg.PreProxyURL = front
			user, password, frontUser, frontPassword := "fixture-user", "fixture-password", "front-user", "front-password"
			if failure == "front-auth" {
				frontPassword = "front-wrong-private"
			}
			if failure == "final-auth" {
				password = "final-wrong-private"
			}
			r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, user, password, frontUser, frontPassword, remoteDependencies{roots: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			c, err := r.DialContext(context.Background(), "tcp", "203.0.113.70:443")
			if c != nil {
				c.Close()
			}
			if err == nil || transientRecoveryFailure(err) {
				t.Fatalf("hard %s failure was admitted or retryable: %v", failure, err)
			}
			var first *preProxyError
			if strings.HasPrefix(failure, "front-") != errors.As(err, &first) {
				t.Fatal("failure lost its hop attribution")
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), u.Host) {
				t.Fatal("failure exposed account or endpoint")
			}
		})
	}
}

func TestPreProxySessionCloseCancelsBothHopHandshakes(t *testing.T) {
	for _, stalledHop := range []string{"first", "final"} {
		t.Run(stalledHop, func(t *testing.T) {
			var finalEndpoint string
			var accepted <-chan struct{}
			if stalledHop == "final" {
				l, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				ready := make(chan struct{})
				accepted = ready
				go func() {
					c, err := l.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					close(ready)
					io.Copy(io.Discard, c)
				}()
				finalEndpoint = "https://" + l.Addr().String()
			} else {
				final := echoHTTPFixture(t, false)
				defer final.Close()
				finalEndpoint = final.URL
			}
			u, _ := url.Parse(finalEndpoint)
			var hits atomic.Int32
			behavior := ""
			if stalledHop == "first" {
				behavior = "stall"
			}
			front, _ := frontProxyFixture(t, "http", u.Host, behavior, &hits)
			cfg := remoteConfig(finalEndpoint)
			cfg.PreProxyURL = front
			r, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "fixture-user", "fixture-password", "front-user", "front-password", remoteDependencies{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			done := make(chan error, 1)
			go func() {
				c, err := r.DialContext(context.Background(), "tcp", "203.0.113.70:443")
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			if stalledHop == "final" {
				select {
				case <-accepted:
				case <-time.After(time.Second):
					t.Fatal("final handshake not reached")
				}
			} else {
				deadline := time.Now().Add(time.Second)
				for hits.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
			}
			r.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("revoked session admitted")
				}
			case <-time.After(300 * time.Millisecond):
				t.Fatal("session closure retained hop socket")
			}
		})
	}
}

func TestPreProxyRecoveryRejectsChangedFirstHop(t *testing.T) {
	final := echoHTTPFixture(t, false)
	defer final.Close()
	u, _ := url.Parse(final.URL)
	var aHits, bHits atomic.Int32
	a, _ := frontProxyFixture(t, "http", u.Host, "", &aHits)
	b, _ := frontProxyFixture(t, "http", u.Host, "", &bHits)
	cfg := remoteConfig(final.URL)
	cfg.PreProxyURL = a
	cfg.ExpectedIPs = []string{"203.0.113.7"}
	original, err := newChainedRemoteRouteWithDependencies(context.Background(), cfg, "fixture-user", "fixture-password", "front-user", "front-password", remoteDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	fp, _ := original.Fingerprint(context.Background())
	cfg.PreProxyURL = b
	s := configured(t)
	_, _, err = s.recoveryCandidate(context.Background(), recoverySnapshot{config: cfg, username: "fixture-user", password: "fixture-password", preUsername: "front-user", prePassword: "front-password", fingerprint: fp, lastVerifiedIP: "203.0.113.7"})
	if !errors.Is(err, errRecoveryPath) || bHits.Load() != 0 {
		t.Fatal("changed chain reached verification or recovered")
	}
}

func TestPreProxyDiagnosticsAttributeFirstHopWithoutSecrets(t *testing.T) {
	s := profileService(t)
	final := echoHTTPFixture(t, false)
	defer final.Close()
	u, _ := url.Parse(final.URL)
	var hits atomic.Int32
	front, _ := frontProxyFixture(t, "http", u.Host, "early-close", &hits)
	p, err := s.SaveRemoteProfile(model.RemoteProfileInput{Name: "Private chain", ProxyURL: final.URL, ExpectedIPs: []string{"203.0.113.7"}, CredentialAction: "replace", Username: "fixture-user", Password: "fixture-password", PreProxyURL: front, PreProxyUsername: "front-user", PreProxyPassword: "front-password"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Check(context.Background()); err == nil {
		t.Fatal("failed chain passed check")
	}
	records := readProbeRecords(t, s)
	last := records[len(records)-1]
	if last["stage"] != "preproxy_http_connect" || last["cause"] != "transport" {
		t.Fatalf("first-hop trace attribution missing: %+v", last)
	}
	encoded, _ := json.Marshal(records)
	for _, secret := range []string{"fixture-user", "fixture-password", "front-user", "front-password", u.Host, front} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("diagnostics exposed chain data")
		}
	}
}
