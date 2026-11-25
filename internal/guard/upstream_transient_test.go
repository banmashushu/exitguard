package guard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSOCKSNegotiationDistinguishesTransportFromHardFailures(t *testing.T) {
	for _, tc := range []struct {
		behavior  string
		transient bool
	}{
		{"timeout", true}, {"early-close", true},
		{"truncated", false}, {"auth-denied", false}, {"bad-method", false},
	} {
		t.Run(tc.behavior, func(t *testing.T) {
			r, err := newRemoteRoute(t.Context(), remoteConfig(socksFixture(t, tc.behavior)), "fixture-user", "fixture-password")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			connection, err := r.DialContext(ctx, "tcp", "203.0.113.70:443")
			if connection != nil {
				connection.Close()
			}
			if err == nil || transientRecoveryFailure(err) != tc.transient {
				t.Fatalf("transient=%v, wanted %v, error=%v", transientRecoveryFailure(err), tc.transient, err)
			}
			if !strings.Contains(safeProbeError(err).Error(), "SOCKS5") {
				t.Fatalf("handshake stage lost in probe: %v", safeProbeError(err))
			}
		})
	}
}

func TestHTTPNegotiationDistinguishesTransportFromHardFailures(t *testing.T) {
	for _, tc := range []struct {
		behavior  string
		transient bool
	}{
		{"timeout", true}, {"early-close", true}, {"truncated", false}, {"auth-denied", false},
	} {
		t.Run(tc.behavior, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				connection, writer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer connection.Close()
				switch tc.behavior {
				case "timeout":
					io.Copy(io.Discard, connection)
				case "truncated":
					io.WriteString(writer, "HTTP/1.1 200 OK\r\n")
					writer.Flush()
				case "auth-denied":
					io.WriteString(writer, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					writer.Flush()
				}
			}))
			defer server.Close()
			r, err := newRemoteRoute(t.Context(), remoteConfig(server.URL), "fixture-user", "fixture-password")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			connection, err := r.DialContext(ctx, "tcp", "203.0.113.70:443")
			if connection != nil {
				connection.Close()
			}
			if err == nil || transientRecoveryFailure(err) != tc.transient {
				t.Fatalf("transient=%v, wanted %v, error=%v", transientRecoveryFailure(err), tc.transient, err)
			}
			if !strings.Contains(safeProbeError(err).Error(), "HTTP") {
				t.Fatalf("handshake stage lost in probe: %v", safeProbeError(err))
			}
		})
	}
}

func TestTypedForwardingTransientUsesExistingVerifiedRecovery(t *testing.T) {
	for _, failure := range []error{
		&forwardError{stage: stageSOCKSHandshake, cause: causeInterrupted},
		&forwardError{stage: stageHTTPHandshake, cause: causeTimeout},
		&forwardError{stage: stageDNS, cause: causeTimeout},
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			h := newRecoveryHarness(t, func(int) (route, error) { return recoveredRoute("203.0.113.7", nil), nil })
			defer h.s.Disarm()
			before := h.s.Status()
			request := httptest.NewRequest("CONNECT", "http://203.0.113.70/", nil)
			h.s.blockProxyFailure(request, before.SessionRevision, failure.Error(), failure)
			tick := h.clock.next(t, 2*time.Second)
			if after := h.s.Status(); after.State != "recovering" || after.SessionRevision == before.SessionRevision {
				t.Fatalf("no revocation/recovery: %+v", after)
			}
			close(tick.release)
			waitRecoveryState(t, h.s, "proxy_active")
		})
	}
}

func TestUnknownForwardingFailureRemainsHard(t *testing.T) {
	const secret = "private-error-detail"
	err := transportFailure(stageDNS, errors.New(secret), true)
	if err.transient() || strings.Contains(err.Error(), secret) {
		t.Fatalf("unknown error became transient or leaked: %v", err)
	}
}

func TestUnclassifiedDialFailureDoesNotBecomeTransientDNSFailure(t *testing.T) {
	// A socket control/binding error can have the same net.OpError envelope as
	// an actual TCP outage. Only the route itself knows which boundary failed.
	source := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("private-interface-control-failure")}
	failure := dnsDialFailure(source)
	if transientRecoveryFailure(failure) || strings.Contains(failure.Error(), "private-interface") {
		t.Fatalf("unclassified socket control failure was retried or leaked: %v", failure)
	}
}

func TestUnclassifiedRequestTransportDoesNotStartRecovery(t *testing.T) {
	h := newRecoveryHarness(t, func(int) (route, error) { return recoveredRoute("203.0.113.7", nil), nil })
	defer h.s.Disarm()
	source := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("interface binding failure")}
	request := httptest.NewRequest("CONNECT", "http://203.0.113.70/", nil)
	h.s.blockProxyFailure(request, h.s.Status().SessionRevision, "连接失败", source)
	if after := h.s.Status(); after.State != "blocked" {
		t.Fatalf("unclassified socket control failure started recovery: %+v", after)
	}
}
