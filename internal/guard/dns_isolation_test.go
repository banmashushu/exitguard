package guard

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTransientDNSExchangePreservesOtherConnections(t *testing.T) {
	for _, failure := range []uint32{1, 2, 3, 4} {
		t.Run([]string{"", "early-close", "http-503", "http-429", "truncated-body"}[failure], func(t *testing.T) {
			f := newDestinationFixture(t)
			echo, echoed := f.echo(t)
			before := f.s.Status()
			f.dnsFailure.Store(failure)
			response, err := f.client.Get("http://example.com/")
			if err != nil {
				t.Fatalf("DNS-only failure closed the proxy connection: %v; state=%+v", err, f.s.Status())
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "DNS") || strings.Contains(string(body), "private-dns-response") {
				t.Fatalf("unsafe or incorrect DNS diagnostic: HTTP %d %q", response.StatusCode, body)
			}
			if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
				t.Fatalf("DNS exchange revoked the verified session: %+v", after)
			}
			assertEchoSurvives(t, echo, echoed)
			f.dnsFailure.Store(0)
			f.healthy(t)
		})
	}
}

func TestDNSFailureDuringHealthStillRevokesAndRevalidates(t *testing.T) {
	f := newDestinationFixture(t)
	optInRecovery(t, f.s, "proxy-only")
	clock := newRecoveryClock()
	f.s.recoveryWait = clock.wait
	if err := f.s.Arm(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer f.s.Disarm()
	echo, echoed := f.echo(t)
	before := f.s.Status()
	f.dnsFailure.Store(2)
	f.s.health(t.Context())
	tick := clock.next(t, 2*time.Second)
	if after := f.s.Status(); after.State != "recovering" || after.SessionRevision == before.SessionRevision || !strings.Contains(after.Reason, "DNS") {
		t.Fatalf("health DNS error was treated as an ordinary request: %+v", after)
	}
	echo.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := echoed.ReadByte(); err == nil {
		t.Fatal("health recovery retained a previously admitted connection")
	}
	f.dnsFailure.Store(0)
	close(tick.release)
	if after := waitRecoveryState(t, f.s, "proxy_active"); after.ObservedIP != "203.0.113.7" {
		t.Fatalf("recovery lost original exit: %+v", after)
	}
	f.healthy(t)
}

func TestDNSTimeoutOnlyLocalAfterVerifiedResolverConnection(t *testing.T) {
	for _, established := range []bool{false, true} {
		t.Run(map[bool]string{false: "during-upstream-dial", true: "after-resolver-TLS"}[established], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				<-r.Context().Done()
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 100 * time.Millisecond
			if !established {
				transport := client.Transport.(*http.Transport).Clone()
				release, exited := make(chan struct{}), make(chan struct{})
				transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
					defer close(exited)
					<-release // Deliberately finish after http.Client has timed out.
					return nil, &upstreamError{"SOCKS5 代理握手或认证失败"}
				}
				client.Transport = transport
				defer transport.CloseIdleConnections()
				defer func() { close(release); <-exited }()
			}
			_, err := queryIPv4(t.Context(), "example.com", server.URL, client)
			var failure *forwardError
			if !errors.As(err, &failure) || failure.cause != causeTimeout || failure.requestLocal() != established {
				t.Fatalf("timeout lost its connection boundary: established=%v err=%v", established, err)
			}
		})
	}
}

func TestDNSHardHeadersCannotBeHiddenByBodyTimeout(t *testing.T) {
	for _, tc := range []struct {
		status      int
		contentType string
	}{
		{http.StatusForbidden, "text/plain"},
		{http.StatusOK, "text/plain"},
		{http.StatusOK, "application/dns-message-invalid"},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", tc.contentType)
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(tc.status)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		client := server.Client()
		client.Timeout = 50 * time.Millisecond
		_, err := queryIPv4(t.Context(), "example.com", server.URL, client)
		server.Close()
		if err == nil || transientRecoveryFailure(err) || !strings.Contains(err.Error(), "DNS") {
			t.Fatalf("hard HTTP status/MIME was masked by the body: status=%d type=%s err=%v", tc.status, tc.contentType, err)
		}
	}
}

func TestDNSCertificateFailureRemainsHard(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	_, err := queryIPv4(t.Context(), "example.com", server.URL, client)
	if err == nil || transientRecoveryFailure(err) || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("resolver certificate failure was made transient: %v", err)
	}
}

func TestHardUpstreamFailuresStayBlockedWithRecoveryEnabled(t *testing.T) {
	for _, failure := range []string{"authentication", "partial-negative-reply", "malformed-DNS"} {
		t.Run(failure, func(t *testing.T) {
			f := newDestinationFixture(t)
			optInRecovery(t, f.s, "proxy-only")
			if err := f.s.Arm(t.Context()); err != nil {
				t.Fatal(err)
			}
			echo, echoed := f.echo(t)
			switch failure {
			case "authentication":
				f.authDenied.Store(true)
			case "partial-negative-reply":
				f.reply.Store(5)
				f.malformed.Store(true)
			case "malformed-DNS":
				f.badDNS.Store(true)
			}
			if response, err := f.client.Get("http://example.com/"); err == nil {
				response.Body.Close()
			}
			if after := f.s.Status(); after.State != "blocked" {
				t.Fatalf("hard failure started automatic recovery: %+v", after)
			}
			echo.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := echoed.ReadByte(); err == nil {
				t.Fatal("hard failure retained another admitted connection")
			}
		})
	}
}

func TestHardDNSExchangeStillClosesWithRecoveryEnabled(t *testing.T) {
	for _, failure := range []uint32{5, 6} {
		t.Run([]string{"", "", "", "", "", "forbidden", "wrong-mime-truncated-body"}[failure], func(t *testing.T) {
			f := newDestinationFixture(t)
			optInRecovery(t, f.s, "proxy-only")
			if err := f.s.Arm(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.dnsFailure.Store(failure)
			if response, err := f.client.Get("http://example.com/"); err == nil {
				response.Body.Close()
			}
			state := f.s.Status()
			if state.State != "blocked" || !strings.Contains(state.Reason, "DNS") || strings.Contains(state.Reason, "private-dns-response") {
				t.Fatalf("hard DNS failure was hidden or made recoverable: %+v", state)
			}
		})
	}
}
