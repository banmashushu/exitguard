package guard

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"exitguard/internal/model"
)

// The only sockets opened by this fixture are loopback sockets. Documentation
// addresses are protocol payloads mapped by the controlled SOCKS server.
type destinationFixture struct {
	s          *Service
	client     *http.Client
	reply      atomic.Uint32
	malformed  atomic.Bool
	badDNS     atomic.Bool
	stallBody  atomic.Bool
	authDenied atomic.Bool
	stop       func()
	stalled    chan struct{}
}

type failedDialRoute struct {
	testRoute
	dialErr error
}

func (r *failedDialRoute) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, r.dialErr
}

func newDestinationFixture(t *testing.T) *destinationFixture {
	t.Helper()
	f := &destinationFixture{stalled: make(chan struct{})}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.stallBody.Load() {
			close(f.stalled)
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "healthy-origin")
	}))
	t.Cleanup(origin.Close)
	probe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"203.0.113.7"}`)
	}))
	t.Cleanup(probe.Close)
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		name, _, e := dnsName(q, 12)
		if e != nil {
			http.Error(w, "bad fixture question", 400)
			return
		}
		answer := append([]byte(nil), q...)
		binary.BigEndian.PutUint16(answer[2:4], 0x8180)
		if name == "missing.invalid" {
			binary.BigEndian.PutUint16(answer[2:4], 0x8183)
		} else if name == "cname-only.invalid" {
			binary.BigEndian.PutUint16(answer[6:8], 1)
			answer = append(answer, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 14, 4, 'n', 'o', '-', 'a', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0)
		} else if name != "no-a.invalid" {
			binary.BigEndian.PutUint16(answer[6:8], 1)
			if name == "multiple-a.invalid" {
				binary.BigEndian.PutUint16(answer[6:8], 2)
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 71)
			}
			last := byte(70)
			if name == "refused.invalid" {
				last = 71
			}
			answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, last)
		}
		if f.badDNS.Load() {
			answer[0] ^= 1
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer)
	}))
	t.Cleanup(doh.Close)
	mapping := map[string]string{
		"203.0.113.53:443": strings.TrimPrefix(doh.URL, "https://"),
		"203.0.113.70:443": strings.TrimPrefix(probe.URL, "https://"),
		"203.0.113.70:80":  strings.TrimPrefix(origin.URL, "http://"),
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var stopOnce sync.Once
	f.stop = func() { stopOnce.Do(func() { l.Close() }) }
	var sessions sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				var greeting [3]byte
				if _, e := io.ReadFull(c, greeting[:]); e != nil || greeting != [3]byte{5, 1, 2} {
					return
				}
				c.Write([]byte{5, 2})
				var head [2]byte
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
				password := make([]byte, int(n[0]))
				if _, e := io.ReadFull(c, password); e != nil {
					return
				}
				if string(user) != "fixture-user" || string(password) != "fixture-password" || f.authDenied.Load() {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				var request [10]byte
				if _, e := io.ReadFull(c, request[:]); e != nil || request[0] != 5 || request[1] != 1 || request[3] != 1 {
					return
				}
				target := net.JoinHostPort(net.IP(request[4:8]).String(), fmt.Sprint(binary.BigEndian.Uint16(request[8:])))
				if target == "203.0.113.72:80" {
					close(f.stalled)
					io.Copy(io.Discard, c) // The client cancellation must close this handshake.
					return
				}
				reply := byte(f.reply.Load())
				address, exists := mapping[target]
				if reply == 0 && !exists {
					reply = 5 // A complete, authenticated target-connection refusal.
				}
				if reply != 0 {
					if f.malformed.Load() {
						c.Write([]byte{5, reply, 0, 1}) // No complete bound address/port.
						return
					}
					c.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				up, e := net.DialTimeout("tcp4", address, time.Second)
				if e != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{}, 2)
				go func() { io.Copy(up, c); done <- struct{}{} }()
				go func() { io.Copy(c, up); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	t.Cleanup(func() { f.stop(); <-acceptDone; sessions.Wait() })
	f.s = configured(t)
	c := remoteConfig("socks5://" + l.Addr().String())
	c.ProxyPort, c.ExpectedIPs = f.s.Config().ProxyPort, []string{"203.0.113.7"}
	c.ProbeURL, c.DNSResolverURL, c.DNSBootstrapIP = "https://example.com/ip", "https://example.com/dns-query", "203.0.113.53"
	if e := f.s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	if e := f.s.SetProxyCredentials("fixture-user", "fixture-password"); e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(probe.Certificate())
	roots.AddCert(doh.Certificate())
	f.s.makeRemoteRoute = func(ctx context.Context, c model.Config, user, password string) (route, error) {
		return newRemoteRouteWithDependencies(ctx, c, user, password, remoteDependencies{roots: roots})
	}
	if e := f.s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	proxy, _ := url.Parse("http://" + f.s.Status().ProxyAddress)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	f.client = &http.Client{Transport: transport, Timeout: time.Second}
	return f
}

func (f *destinationFixture) healthy(t *testing.T) {
	t.Helper()
	resp, e := f.client.Get("http://203.0.113.70/")
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "healthy-origin" {
		t.Fatalf("healthy target failed: status=%d body=%q state=%+v", resp.StatusCode, body, f.s.Status())
	}
}

func TestTargetFailureDoesNotRevokeHealthySOCKS5Session(t *testing.T) {
	cases := []struct {
		name, target string
		reply        uint32
	}{
		{"ruleset", "203.0.113.71", 2},
		{"network-unreachable", "203.0.113.71", 3},
		{"host-unreachable", "203.0.113.71", 4},
		{"connection-refused", "203.0.113.71", 5},
		{"resolved-target-refused", "refused.invalid", 0},
		{"ttl-expired", "203.0.113.71", 6},
		{"nxdomain", "missing.invalid", 0},
		{"empty-a", "no-a.invalid", 0},
		{"cname-without-a", "cname-only.invalid", 0},
	}
	for _, tc := range cases {
		for _, method := range []string{"HTTP", "CONNECT"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				f := newDestinationFixture(t)
				f.healthy(t)
				before := f.s.Status()
				f.reply.Store(tc.reply)
				if method == "HTTP" {
					resp, e := f.client.Get("http://" + tc.target + "/")
					if e != nil {
						t.Fatalf("target failure should return a local 502 response: %v; status=%+v", e, f.s.Status())
					}
					resp.Body.Close()
					if resp.StatusCode != http.StatusBadGateway {
						t.Fatalf("target failure response: %d", resp.StatusCode)
					}
				} else {
					target := tc.target + ":443"
					res := proxyRaw(t, f.s, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
					if !strings.Contains(res, "502 Bad Gateway") {
						t.Fatalf("CONNECT target failure should return local 502: %q; status=%+v", res, f.s.Status())
					}
				}
				if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
					t.Fatalf("single target revoked healthy exit: before=%+v after=%+v", before, after)
				}
				events := f.s.Events()
				if last := events[len(events)-1].Message; !strings.Contains(last, "仅拒绝此请求") || strings.Contains(last, tc.target) || strings.Contains(last, "fixture-") {
					t.Fatalf("request-local diagnostic missing or contains endpoint/credentials: %q", last)
				}
				f.reply.Store(0)
				f.healthy(t)
			})
		}
	}
}

func TestTargetRefusalStillTriesOtherIPv4OnSameSOCKS5Route(t *testing.T) {
	f := newDestinationFixture(t)
	before := f.s.Status()
	resp, e := f.client.Get("http://multiple-a.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "healthy-origin" {
		t.Fatalf("same-route second IPv4 not tried: status=%d body=%q", resp.StatusCode, body)
	}
	if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
		t.Fatalf("same-route retry revoked exit: %+v", after)
	}
}

func TestCancelledDownstreamRequestDoesNotRevokeSOCKS5Session(t *testing.T) {
	for _, phase := range []string{"upstream-handshake", "origin-response"} {
		t.Run(phase, func(t *testing.T) {
			f := newDestinationFixture(t)
			f.healthy(t)
			before := f.s.Status()
			target := "203.0.113.72"
			if phase == "origin-response" {
				f.stallBody.Store(true)
				target = "203.0.113.70"
			}
			down, e := net.DialTimeout("tcp4", f.s.Status().ProxyAddress, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer down.Close()
			if _, e = io.WriteString(down, "GET http://"+target+"/ HTTP/1.1\r\nHost: "+target+"\r\nConnection: close\r\n\r\n"); e != nil {
				t.Fatal(e)
			}
			select {
			case <-f.stalled:
			case <-time.After(time.Second):
				t.Fatal("controlled upstream handshake never stalled")
			}
			down.Close()
			// Wait for this request's handler to finish, not merely for the local client
			// to close. ConnState removes its tracked downstream after handler return.
			deadline := time.Now().Add(time.Second)
			for {
				f.s.mu.Lock()
				pending := len(f.s.connections)
				f.s.mu.Unlock()
				if pending == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cancelled request retained an active connection")
				}
				time.Sleep(time.Millisecond)
			}
			if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
				t.Fatalf("client cancellation revoked healthy exit: before=%+v after=%+v", before, after)
			}
			f.stallBody.Store(false)
			f.healthy(t)
		})
	}
}

func TestUpstreamFailuresStillRevokeSOCKS5Session(t *testing.T) {
	for _, failure := range []string{"auth", "general-failure", "unsupported-command", "invalid-reply", "truncated-target-rejection", "malformed-dns", "transport"} {
		t.Run(failure, func(t *testing.T) {
			f := newDestinationFixture(t)
			f.healthy(t)
			target := "203.0.113.70"
			switch failure {
			case "auth":
				f.authDenied.Store(true)
			case "general-failure":
				f.reply.Store(1)
			case "unsupported-command":
				f.reply.Store(7)
			case "invalid-reply":
				f.reply.Store(255)
			case "truncated-target-rejection":
				f.reply.Store(5)
				f.malformed.Store(true)
			case "malformed-dns":
				f.badDNS.Store(true)
				target = "example.com"
			case "transport":
				f.stop()
			}
			if resp, e := f.client.Get("http://" + target + "/"); e == nil {
				resp.Body.Close()
				t.Fatal("untrusted upstream admitted request")
			}
			if after := f.s.Status(); after.State != "blocked" {
				t.Fatalf("upstream failure retained entry: %+v", after)
			}
		})
	}
}

func TestIndependentUpstreamTimeoutOrCancellationStillBlocksLiveRequest(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			s := configured(t)
			s.makeRoute = func(model.Config, string) (route, error) {
				return &failedDialRoute{testRoute: testRoute{ip: "203.0.113.7"}, dialErr: failure}, nil
			}
			if e := s.Arm(context.Background()); e != nil {
				t.Fatal(e)
			}
			proxyRaw(t, s, "GET http://203.0.113.70/ HTTP/1.1\r\nHost: 203.0.113.70\r\nConnection: close\r\n\r\n")
			if st := s.Status(); st.State != "blocked" {
				t.Fatalf("upstream failure on live downstream request retained admission: %+v", st)
			}
		})
	}
}
