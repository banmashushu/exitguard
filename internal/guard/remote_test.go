package guard

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"exitguard/internal/model"
)

func remoteConfig(raw string) model.Config {
	return defaults(model.Config{Mode: "remote", EnforcementMode: "proxy-only", ProxyURL: raw, ProxyPort: 17890})
}
func echoHTTPFixture(t *testing.T, secure bool) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "203.0.113.70:443" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password")) {
			w.WriteHeader(407)
			return
		}
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(b, "HTTP/1.1 200 Connection Established\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
	})
	if secure {
		s := httptest.NewUnstartedServer(h)
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.StartTLS()
		return s
	}
	return httptest.NewServer(h)
}
func assertRemoteEcho(t *testing.T, r route) {
	t.Helper()
	c, e := r.DialContext(context.Background(), "tcp", "203.0.113.70:443")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	payload := "opaque upstream tunnel\x00"
	if _, e = io.WriteString(c, payload); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len(payload))
	if _, e = io.ReadFull(c, b); e != nil || string(b) != payload {
		t.Fatalf("changed tunnel bytes: %q %v", b, e)
	}
}
func TestRemoteHTTPAndVerifiedHTTPSAuthentication(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			srv := echoHTTPFixture(t, secure)
			defer srv.Close()
			roots := x509.NewCertPool()
			if secure {
				roots.AddCert(srv.Certificate())
			}
			r, e := newRemoteRouteWithDependencies(context.Background(), remoteConfig(srv.URL), "fixture-user", "fixture-password", remoteDependencies{roots: roots})
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			assertRemoteEcho(t, r)
			wrong, e := newRemoteRouteWithDependencies(context.Background(), remoteConfig(srv.URL), "fixture-user", "wrong-password", remoteDependencies{roots: roots})
			if e != nil {
				t.Fatal(e)
			}
			defer wrong.Close()
			if c, e := wrong.DialContext(context.Background(), "tcp", "203.0.113.70:443"); e == nil {
				c.Close()
				t.Fatal("auth denial admitted")
			}
			if secure {
				untrusted, e := newRemoteRoute(context.Background(), remoteConfig(srv.URL), "fixture-user", "fixture-password")
				if e != nil {
					t.Fatal(e)
				}
				defer untrusted.Close()
				if c, e := untrusted.DialContext(context.Background(), "tcp", "203.0.113.70:443"); e == nil {
					c.Close()
					t.Fatal("untrusted TLS accepted")
				}
				_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
				wrongName, e := newRemoteRouteWithDependencies(context.Background(), remoteConfig("https://wrong-name.example:"+port), "fixture-user", "fixture-password", remoteDependencies{roots: roots, lookupIP: func(context.Context, string, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("127.0.0.1")}, nil
				}})
				if e != nil {
					t.Fatal(e)
				}
				defer wrongName.Close()
				if c, e := wrongName.DialContext(context.Background(), "tcp", "203.0.113.70:443"); e == nil {
					c.Close()
					t.Fatal("TLS certificate hostname mismatch accepted")
				}
			}
		})
	}
}

func socksFixture(t *testing.T, behavior string) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				var head [2]byte
				if _, e := io.ReadFull(c, head[:]); e != nil {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, e := io.ReadFull(c, methods); e != nil {
					return
				}
				if behavior == "timeout" {
					<-stop
					return
				}
				if behavior == "bad-method" {
					c.Write([]byte{5, 1})
					return
				}
				if behavior == "no-auth" {
					c.Write([]byte{5, 0})
				} else {
					c.Write([]byte{5, 2})
					if _, e := io.ReadFull(c, head[:]); e != nil {
						return
					}
					user := make([]byte, int(head[1]))
					if _, e := io.ReadFull(c, user); e != nil {
						return
					}
					var n [1]byte
					if _, e := io.ReadFull(c, n[:]); e != nil {
						return
					}
					pass := make([]byte, int(n[0]))
					if _, e := io.ReadFull(c, pass); e != nil {
						return
					}
					if string(user) != "fixture-user" || string(pass) != "fixture-password" || behavior == "auth-denied" {
						c.Write([]byte{1, 1})
						return
					}
					c.Write([]byte{1, 0})
				}
				var request [10]byte
				if _, e := io.ReadFull(c, request[:]); e != nil {
					return
				}
				if request[0] != 5 || request[1] != 1 || request[3] != 1 || net.IP(request[4:8]).String() != "203.0.113.70" || binary.BigEndian.Uint16(request[8:]) != 443 {
					return
				}
				if behavior == "truncated" {
					c.Write([]byte{5, 0, 0})
					return
				}
				if behavior == "connect-denied" {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { close(stop); l.Close(); <-acceptDone; wg.Wait() })
	return "socks5://" + l.Addr().String()
}
func TestRemoteSOCKS5RFC1929AndBoundedFailures(t *testing.T) {
	for _, behavior := range []string{"success", "no-auth", "bad-method", "auth-denied", "truncated", "connect-denied", "timeout"} {
		t.Run(behavior, func(t *testing.T) {
			user, password := "fixture-user", "fixture-password"
			if behavior == "no-auth" {
				user, password = "", ""
			}
			r, e := newRemoteRoute(context.Background(), remoteConfig(socksFixture(t, behavior)), user, password)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			if behavior == "success" || behavior == "no-auth" {
				assertRemoteEcho(t, r)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if c, e := r.DialContext(ctx, "tcp", "203.0.113.70:443"); e == nil {
				c.Close()
				t.Fatalf("accepted %s", behavior)
			}
		})
	}
}

func TestRemoteEndpointValidationPinningAndSelfRecursion(t *testing.T) {
	for _, raw := range []string{"http://u:secret@proxy.example:80", "http://proxy.example", "http://proxy.example:80/", "socks5h://proxy.example:1080", "https://proxy.example:0", "http://[::1]:80", "http://proxy.example:80?password=x", "http://proxy.example:80#x"} {
		if _, e := remoteProxyURL(raw); e == nil {
			t.Fatalf("accepted malformed remote URL %q", raw)
		}
	}
	srv := echoHTTPFixture(t, false)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	calls := 0
	r, e := newRemoteRouteWithDependencies(context.Background(), remoteConfig("http://pinned.example:"+port), "fixture-user", "fixture-password", remoteDependencies{lookupIP: func(context.Context, string, string) ([]net.IP, error) {
		calls++
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	assertRemoteEcho(t, r)
	assertRemoteEcho(t, r)
	if calls != 1 {
		t.Fatal("remote proxy DNS was not pinned for route")
	}
	c := remoteConfig("http://localhost:17890")
	if r, e := newRemoteRoute(context.Background(), c, "", ""); e == nil {
		r.Close()
		t.Fatal("recursive upstream accepted")
	}
}

func TestLocalRelayRefusesGuardSelfRecursion(t *testing.T) {
	c := remoteConfig("http://127.0.0.1:17890")
	c.Mode = "proxy"
	if r, e := newRoute(c, ""); e == nil {
		r.Close()
		t.Fatal("local relay points recursively at guard listener")
	}
}

func TestRemoteHTTPTruncationAndTimeout(t *testing.T) {
	for _, behavior := range []string{"truncated", "timeout"} {
		t.Run(behavior, func(t *testing.T) {
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				http.ReadRequest(bufio.NewReader(c))
				if behavior == "truncated" {
					io.WriteString(c, "HTTP/1.1 200 OK\r\n")
					return
				}
				io.Copy(io.Discard, c)
			}()
			r, e := newRemoteRoute(context.Background(), remoteConfig("http://"+l.Addr().String()), "", "")
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if c, e := r.DialContext(ctx, "tcp", "203.0.113.70:443"); e == nil {
				c.Close()
				t.Fatal("accepted incomplete handshake")
			}
			<-done
		})
	}
}

func TestRemoteHTTPAcceptsSuccessfulCONNECTResponses(t *testing.T) {
	for _, status := range []int{200, 201, 204, 299} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, b, e := w.(http.Hijacker).Hijack()
				if e != nil {
					return
				}
				defer c.Close()
				fmt.Fprintf(b, "HTTP/1.1 %d Tunnel\r\nContent-Length: 999\r\n\r\nopaque", status)
				b.Flush()
				io.Copy(c, b)
			}))
			defer server.Close()
			r, e := newRemoteRoute(context.Background(), remoteConfig(server.URL), "", "")
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			c, e := r.DialContext(context.Background(), "tcp", "203.0.113.70:443")
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			b := make([]byte, len("opaque"))
			if _, e = io.ReadFull(c, b); e != nil || string(b) != "opaque" {
				t.Fatalf("successful CONNECT body metadata consumed tunnel bytes: %q %v", b, e)
			}
		})
	}
}

func TestHTTPSProxyCancellationDuringTLSHandshake(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	accepted, closed := make(chan struct{}), make(chan struct{})
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		defer close(closed)
		close(accepted)
		io.Copy(io.Discard, c)
	}()
	r, e := newRemoteRoute(context.Background(), remoteConfig("https://"+l.Addr().String()), "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		c, e := r.DialContext(ctx, "tcp", "203.0.113.70:443")
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	<-accepted
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled TLS handshake accepted")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("TLS handshake ignored cancellation")
	}
	select {
	case <-closed:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancelled TLS handshake retained upstream connection")
	}
}
