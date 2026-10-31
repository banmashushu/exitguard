package guard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The upstream authentication and tunnels remain real. This test adapter only
// shortens the HTTP exchange deadline so timeout coverage does not wait 60s.
type shortExchangeRoute struct{ route }

func (r *shortExchangeRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, e := r.route.DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	return &shortExchangeConn{Conn: c}, nil
}

type shortExchangeConn struct{ net.Conn }

func (c *shortExchangeConn) SetDeadline(deadline time.Time) error {
	short := time.Now().Add(50 * time.Millisecond)
	if !deadline.IsZero() && deadline.After(short) {
		deadline = short
	}
	return c.Conn.SetDeadline(deadline)
}

func assertEchoSurvives(t *testing.T, c net.Conn, reader io.Reader) {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	const payload = "unrelated-tunnel-still-open"
	if _, e := io.WriteString(c, payload); e != nil {
		t.Fatalf("unrelated tunnel was closed: %v", e)
	}
	b := make([]byte, len(payload))
	if _, e := io.ReadFull(reader, b); e != nil || string(b) != payload {
		t.Fatalf("unrelated tunnel was interrupted: %q %v", b, e)
	}
}

func TestOriginExchangeFailureDoesNotRevokeVerifiedSOCKS5Route(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failure    uint32
		status     int
		streamFail bool
	}{
		{"malformed-status", 1, 502, false},
		{"truncated-head", 2, 502, false},
		{"early-close", 3, 502, false},
		{"oversize-head", 4, 502, false},
		{"informational-flood", 5, 502, false},
		{"response-timeout", 6, 504, false},
		{"truncated-body", 7, 0, true},
		{"body-timeout", 8, 0, true},
		{"malformed-chunks", 9, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDestinationFixture(t)
			f.healthy(t)
			echo, echoed := f.echo(t)
			if tc.failure == 6 || tc.failure == 8 {
				f.s.mu.Lock()
				f.s.activeRoute = &shortExchangeRoute{route: f.s.activeRoute}
				f.s.mu.Unlock()
			}
			before := f.s.Status()
			f.badOrigin.Store(tc.failure)
			resp, e := f.client.Get("http://203.0.113.70/bad-origin")
			if tc.streamFail {
				if e == nil {
					_, e = io.ReadAll(resp.Body)
					resp.Body.Close()
				}
				if e == nil {
					t.Fatal("truncated or malformed response body appeared complete")
				}
			} else {
				if e != nil {
					t.Fatalf("want local HTTP %d, got error %v; status=%+v", tc.status, e, f.s.Status())
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != tc.status || strings.Contains(string(body), "private-origin-detail") {
					t.Fatalf("unsafe or incorrect local response: status=%d body=%q", resp.StatusCode, body)
				}
			}
			if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
				t.Fatalf("origin exchange revoked verified exit: before=%+v after=%+v", before, after)
			}
			assertEchoSurvives(t, echo, echoed)
			f.badOrigin.Store(0)
			f.healthy(t)
		})
	}
}

type repeatedBodyByte struct{}

func (repeatedBodyByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestChunkedClientBodyLimitDoesNotRevokeVerifiedSOCKS5Route(t *testing.T) {
	f := newDestinationFixture(t)
	f.healthy(t)
	echo, echoed := f.echo(t)
	before := f.s.Status()
	f.client.Timeout = 5 * time.Second
	req, e := http.NewRequest("POST", "http://203.0.113.70/drain", io.LimitReader(repeatedBodyByte{}, maxProxyBody+1))
	if e != nil {
		t.Fatal(e)
	}
	resp, e := f.client.Do(req)
	if e != nil {
		t.Fatalf("oversize chunked body should receive local 413: %v; status=%+v", e, f.s.Status())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 413, got %d %q", resp.StatusCode, body)
	}
	if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
		t.Fatalf("client body limit revoked verified exit: %+v", after)
	}
	assertEchoSurvives(t, echo, echoed)
	f.healthy(t)
}

func TestUpstreamAuthenticationFailureStillClosesOtherTunnels(t *testing.T) {
	f := newDestinationFixture(t)
	echo, echoed := f.echo(t)
	f.authDenied.Store(true)
	if resp, e := f.client.Get("http://203.0.113.70/"); e == nil {
		resp.Body.Close()
		t.Fatal("upstream authentication failure admitted request")
	}
	if after := f.s.Status(); after.State != "blocked" {
		t.Fatalf("upstream authentication loss retained route: %+v", after)
	}
	echo.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := echoed.ReadByte(); e == nil {
		t.Fatal("unrelated tunnel survived actual upstream authentication loss")
	}
}

func TestFingerprintLossStillBlocksBeforeDestinationExchange(t *testing.T) {
	s := configured(t)
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	r := s.activeRoute.(*testRoute)
	r.err = fmt.Errorf("controlled route fingerprint lost")
	s.mu.Unlock()
	proxyRaw(t, s, "GET http://203.0.113.70/ HTTP/1.1\r\nHost: 203.0.113.70\r\nConnection: close\r\n\r\n")
	if st := s.Status(); st.State != "blocked" || !strings.Contains(st.Reason, "出口路径变化") {
		t.Fatalf("fingerprint loss did not close admission: %+v", st)
	}
}
