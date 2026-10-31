package guard

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"exitguard/internal/model"
)

type recoveryRoute struct {
	testRoute
	fp     string
	fpFn   func() string
	probe  func(context.Context) (string, error)
	closed atomic.Int32
}

func (r *recoveryRoute) Fingerprint(context.Context) (string, error) {
	if r.fpFn != nil {
		return r.fpFn(), nil
	}
	return r.fp, nil
}
func (r *recoveryRoute) Probe(ctx context.Context, _ string) (string, error) {
	return r.probe(ctx)
}
func (r *recoveryRoute) Close() error { r.closed.Add(1); return nil }

func optInRecovery(t *testing.T, s *Service, mode string) {
	t.Helper()
	wire, _ := json.Marshal(s.Config())
	var values map[string]any
	json.Unmarshal(wire, &values)
	values["autoRecover"], values["enforcementMode"] = true, mode
	wire, _ = json.Marshal(values)
	var c model.Config
	if e := json.Unmarshal(wire, &c); e != nil {
		t.Fatal(e)
	}
	if e := s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
}

func waitRecoveryState(t *testing.T, s *Service, state string) model.Status {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		st := s.Status()
		if st.State == state {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("want state %s, got %+v", state, st)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTransientHealthFailureClosesGateAndStartsOptInRecovery(t *testing.T) {
	s := configured(t)
	optInRecovery(t, s, "proxy-only")
	var fail atomic.Bool
	r := &recoveryRoute{fp: "original-fixed-route", probe: func(context.Context) (string, error) {
		if fail.Load() {
			return "", context.DeadlineExceeded
		}
		return "203.0.113.7", nil
	}}
	s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	defer b.Close()
	if !s.track(a, s.Status().SessionRevision) {
		t.Fatal("initial admission unavailable")
	}
	fail.Store(true)
	s.health(context.Background())
	if st := s.Status(); st.State != "recovering" || st.FilterActive {
		t.Fatalf("known transient failure should revoke admission and recover: %+v", st)
	}
	if r.closed.Load() != 1 {
		t.Fatal("old route was not closed before recovery")
	}
	if _, e := b.Write([]byte("must-close")); e == nil {
		t.Fatal("old active tunnel survived recovery entry")
	}
	if res := proxyRaw(t, s, "GET http://203.0.113.70/ HTTP/1.1\r\nHost: 203.0.113.70\r\n\r\n"); !strings.Contains(res, "503") {
		t.Fatalf("recovering entry forwarded a request: %q", res)
	}
	s.Disarm()
}

func TestUnknownProbeErrorCannotBecomeAutomaticRecovery(t *testing.T) {
	s := configured(t)
	optInRecovery(t, s, "proxy-only")
	var fail atomic.Bool
	r := &recoveryRoute{fp: "original-fixed-route", probe: func(context.Context) (string, error) {
		if fail.Load() {
			return "", errors.New("unknown hard protocol failure")
		}
		return "203.0.113.7", nil
	}}
	s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	fail.Store(true)
	s.health(context.Background())
	if st := s.Status(); st.State != "blocked" {
		t.Fatalf("unknown failure was retried: %+v", st)
	}
}

type recoveryTick struct {
	delay   time.Duration
	release chan struct{}
}

type recoveryClock struct{ ticks chan recoveryTick }

func newRecoveryClock() *recoveryClock { return &recoveryClock{ticks: make(chan recoveryTick, 8)} }
func (c *recoveryClock) wait(ctx context.Context, delay time.Duration) error {
	tick := recoveryTick{delay: delay, release: make(chan struct{})}
	select {
	case c.ticks <- tick:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-tick.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *recoveryClock) next(t *testing.T, delay time.Duration) recoveryTick {
	t.Helper()
	select {
	case tick := <-c.ticks:
		if tick.delay != delay {
			t.Fatalf("retry delay=%s want=%s", tick.delay, delay)
		}
		return tick
	case <-time.After(time.Second):
		t.Fatal("recovery timer was not scheduled")
		return recoveryTick{}
	}
}

type recoveryReply struct {
	ip  string
	err error
}
type recoveryHarness struct {
	s       *Service
	clock   *recoveryClock
	reply   atomic.Pointer[recoveryReply]
	calls   atomic.Int32
	initial *recoveryRoute
}

func newRecoveryHarness(t *testing.T, factory func(int) (route, error)) *recoveryHarness {
	t.Helper()
	h := &recoveryHarness{s: configured(t), clock: newRecoveryClock()}
	optInRecovery(t, h.s, "proxy-only")
	c := h.s.Config()
	c.ExpectedIPs = []string{"203.0.113.7", "203.0.113.8"}
	if e := h.s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	h.reply.Store(&recoveryReply{ip: "203.0.113.7"})
	h.initial = &recoveryRoute{fp: "original-fixed-route", probe: func(context.Context) (string, error) {
		reply := h.reply.Load()
		return reply.ip, reply.err
	}}
	h.s.recoveryWait = h.clock.wait
	h.s.makeRoute = func(model.Config, string) (route, error) {
		call := int(h.calls.Add(1))
		if call == 1 {
			return h.initial, nil
		}
		return factory(call - 1)
	}
	if e := h.s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	return h
}

func (h *recoveryHarness) trigger() {
	h.reply.Store(&recoveryReply{err: context.DeadlineExceeded})
	h.s.health(context.Background())
}

func recoveredRoute(ip string, failure error) *recoveryRoute {
	return &recoveryRoute{fp: "original-fixed-route", probe: func(context.Context) (string, error) { return ip, failure }}
}

func waitRecoveryWorkerExit(t *testing.T, s *Service) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(s.recoverySlot) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("cancelled recovery worker did not release its slot")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRecoveryRestoresOnlyFreshlyVerifiedOriginalIdentity(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	candidate := recoveredRoute("203.0.113.7", nil)
	candidate.probe = func(ctx context.Context) (string, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 15*time.Second || time.Until(deadline) < 14*time.Second {
			return "", errors.New("recovery validation lacks 15s bound")
		}
		close(entered)
		<-release
		return "203.0.113.7", nil
	}
	h := newRecoveryHarness(t, func(int) (route, error) { return candidate, nil })
	before := h.s.Status()
	h.trigger()
	tick := h.clock.next(t, 2*time.Second)
	if st := h.s.Status(); st.RecoveryAttempt != 1 || st.RecoveryMaxAttempts != 3 || st.NextRetryAt == "" || st.State != "recovering" || st.SessionRevision == before.SessionRevision {
		t.Fatalf("recovery schedule not exposed or admission not revoked: %+v", st)
	}
	close(tick.release)
	<-entered
	if _, _, open := h.s.admission(); open {
		t.Fatal("forwarding reopened before candidate probe completed")
	}
	close(release)
	st := waitRecoveryState(t, h.s, "proxy_active")
	if st.ObservedIP != "203.0.113.7" || st.FilterActive || st.PolicyHash != "" || st.RecoveryAttempt != 0 || st.NextRetryAt != "" || candidate.closed.Load() != 0 {
		t.Fatalf("invalid restored proxy-only state: %+v closed=%d", st, candidate.closed.Load())
	}
	if h.calls.Load() != 2 || h.initial.closed.Load() != 1 {
		t.Fatal("recovery did not use exactly one fresh route")
	}
}

func TestRecoveryRejectsChangedFingerprintOrOtherAllowedIP(t *testing.T) {
	for _, change := range []string{"before-path", "after-path", "other-allowed-ip"} {
		t.Run(change, func(t *testing.T) {
			candidate := recoveredRoute("203.0.113.7", nil)
			switch change {
			case "before-path":
				candidate.fp = "changed-path"
			case "after-path":
				var fingerprints atomic.Int32
				candidate.fpFn = func() string {
					if fingerprints.Add(1) == 1 {
						return "original-fixed-route"
					}
					return "changed-path"
				}
			case "other-allowed-ip":
				candidate = recoveredRoute("203.0.113.8", nil)
			}
			h := newRecoveryHarness(t, func(int) (route, error) { return candidate, nil })
			h.trigger()
			tick := h.clock.next(t, 2*time.Second)
			close(tick.release)
			st := waitRecoveryState(t, h.s, "blocked")
			if !strings.Contains(st.Reason, "原") || h.calls.Load() != 2 || candidate.closed.Load() != 1 {
				t.Fatalf("identity drift was retried or candidate leaked: %+v calls=%d closed=%d", st, h.calls.Load(), candidate.closed.Load())
			}
			if !reflect.DeepEqual(h.s.Config().ExpectedIPs, []string{"203.0.113.7", "203.0.113.8"}) {
				t.Fatal("recovery changed expected IP policy")
			}
		})
	}
}

func TestRecoveryExhaustsThreeAttemptsAndClosesEveryCandidate(t *testing.T) {
	candidates := make(chan *recoveryRoute, 3)
	h := newRecoveryHarness(t, func(int) (route, error) {
		r := recoveredRoute("", &probeError{kind: probeHTTPStatus, status: 503})
		candidates <- r
		return r, nil
	})
	h.trigger()
	for _, delay := range []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second} {
		tick := h.clock.next(t, delay)
		close(tick.release)
	}
	st := waitRecoveryState(t, h.s, "blocked")
	if !strings.Contains(st.Reason, "重试已用尽（3 次）") || h.calls.Load() != 4 || st.NextRetryAt != "" || st.RecoveryAttempt != 0 {
		t.Fatalf("retry bound not enforced: %+v calls=%d", st, h.calls.Load())
	}
	for i := 0; i < 3; i++ {
		if candidate := <-candidates; candidate.closed.Load() != 1 {
			t.Fatal("failed candidate was not closed exactly once")
		}
	}
}

func TestRecoveryCancellationWhileWaitingCannotRestart(t *testing.T) {
	for _, action := range []string{"pause", "save", "check", "credentials", "secret", "shutdown"} {
		t.Run(action, func(t *testing.T) {
			h := newRecoveryHarness(t, func(int) (route, error) { return recoveredRoute("203.0.113.7", nil), nil })
			h.trigger()
			tick := h.clock.next(t, 2*time.Second)
			switch action {
			case "pause":
				h.s.Disarm()
			case "save":
				if e := h.s.SaveConfig(h.s.Config()); e != nil {
					t.Fatal(e)
				}
			case "check":
				if e := h.s.Check(context.Background()); e != nil {
					t.Fatal(e)
				}
			case "credentials":
				if e := h.s.SetProxyCredentials("", ""); e != nil {
					t.Fatal(e)
				}
			case "secret":
				h.s.SetSecret("new-session-only-secret")
			case "shutdown":
				h.s.mu.Lock()
				h.s.listener.Close()
				h.s.mu.Unlock()
				waitRecoveryState(t, h.s, "stopped")
			}
			before := h.s.Status()
			close(tick.release)
			waitRecoveryWorkerExit(t, h.s)
			if after := h.s.Status(); !reflect.DeepEqual(after, before) {
				t.Fatalf("cancelled worker changed current state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestLateRecoveryCandidateCannotReviveAfterUserChange(t *testing.T) {
	for _, action := range []string{"pause", "save", "credentials", "check"} {
		t.Run(action, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			candidate := recoveredRoute("203.0.113.7", nil)
			candidate.probe = func(context.Context) (string, error) { close(entered); <-release; return "203.0.113.7", nil }
			h := newRecoveryHarness(t, func(attempt int) (route, error) {
				if attempt == 1 {
					return candidate, nil
				}
				return recoveredRoute("203.0.113.7", nil), nil
			})
			h.trigger()
			tick := h.clock.next(t, 2*time.Second)
			close(tick.release)
			<-entered
			switch action {
			case "pause":
				h.s.Disarm()
			case "save":
				h.s.SaveConfig(h.s.Config())
			case "credentials":
				h.s.SetProxyCredentials("", "")
			case "check":
				if e := h.s.Check(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			before := h.s.Status()
			close(release)
			waitRecoveryWorkerExit(t, h.s)
			if after := h.s.Status(); !reflect.DeepEqual(after, before) || candidate.closed.Load() != 1 {
				t.Fatalf("late candidate revived or leaked: before=%+v after=%+v closed=%d", before, after, candidate.closed.Load())
			}
		})
	}
}

func TestRecoveryTransientClassificationRequiresKnownTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"timeout", context.DeadlineExceeded, true},
		{"network-op", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection interrupted")}, true},
		{"connection-reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, true},
		{"remote-tls-alert", &net.OpError{Op: "remote error", Err: errors.New("TLS protocol alert")}, false},
		{"nested-local-tls-alert", &net.OpError{Op: "read", Err: &net.OpError{Op: "local error", Err: errors.New("TLS protocol alert")}}, false},
		{"exported-tls-alert", &net.OpError{Op: "read", Err: tls.AlertError(40)}, false},
		{"read-interruption", &probeError{kind: probeBodyRead}, true},
		{"429", &probeError{kind: probeHTTPStatus, status: 429}, true},
		{"503", &probeError{kind: probeHTTPStatus, status: 503}, true},
		{"tcp-unreachable", &upstreamError{"指定代理上游不可达"}, true},
		{"raw-unknown", errors.New("unrecognized protocol failure"), false},
		{"sanitized-unknown", safeProbeError(errors.New("unrecognized failure")), false},
		{"unknown-read", &probeError{kind: probeUnknownReadFailure}, false},
		{"auth-or-protocol", &upstreamError{"SOCKS5 代理握手或认证失败"}, false},
		{"tls", &upstreamError{"HTTPS 代理证书或 TLS 握手验证失败"}, false},
		{"invalid-content", &probeError{kind: probeInvalidContent}, false},
		{"invalid-ip", &probeError{kind: probeInvalidIP}, false},
		{"403", &probeError{kind: probeHTTPStatus, status: 403}, false},
		{"cancelled", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := transientRecoveryFailure(tc.err); got != tc.want {
				t.Fatalf("transient=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestRecoveryOptInMigrationStrictModeAndNoRestartAutostart(t *testing.T) {
	s := configured(t)
	if s.Config().AutoRecover {
		t.Fatal("legacy config unexpectedly opts into recovery")
	}
	c := s.Config()
	c.AutoRecover = true
	if e := s.SaveConfig(c); e == nil {
		t.Fatal("strict mode accepted unsupported automatic recovery")
	}
	optInRecovery(t, s, "proxy-only")
	next, e := New(s.configPath)
	if e != nil {
		t.Fatal(e)
	}
	if !next.Config().AutoRecover || next.Status().State != "unconfigured" || next.armedIntent {
		t.Fatalf("restart unexpectedly created active intent: %+v", next.Status())
	}
}

func TestRealSOCKS5RecoveryClosesThenRestoresSameAuthenticatedExit(t *testing.T) {
	f := newDestinationFixture(t)
	clock := newRecoveryClock()
	f.s.recoveryWait = clock.wait
	optInRecovery(t, f.s, "proxy-only")
	if e := f.s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.healthy(t)
	echo, echoed := f.echo(t)
	before := f.s.Status()
	f.stop() // Refuse new TCP connections only on this test-owned endpoint.
	if resp, e := f.client.Get("http://203.0.113.70/"); e == nil {
		resp.Body.Close()
		t.Fatal("stopped upstream forwarded a request")
	}
	st := waitRecoveryState(t, f.s, "recovering")
	if st.SessionRevision == before.SessionRevision || st.FilterActive {
		t.Fatal("recovery did not revoke the previous admission")
	}
	echo.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := echoed.ReadByte(); e == nil {
		t.Fatal("existing tunnel survived upstream recovery revocation")
	}
	if res := proxyRaw(t, f.s, "GET http://203.0.113.70/ HTTP/1.1\r\nHost: 203.0.113.70\r\n\r\n"); !strings.Contains(res, "503") {
		t.Fatalf("recovering gate was open: %q", res)
	}
	tick := clock.next(t, 2*time.Second)
	if e := f.restart(); e != nil {
		t.Fatal(e)
	}
	close(tick.release)
	st = waitRecoveryState(t, f.s, "proxy_active")
	if st.ObservedIP != before.ObservedIP || st.FilterActive || !st.UpstreamCredentialsSet {
		t.Fatalf("recovery lost original exit/authentication or overstated proof: %+v", st)
	}
	f.healthy(t)
}

func TestHardFailureDuringRecoveryStopsWithoutAnotherRetry(t *testing.T) {
	for _, failure := range []error{
		&upstreamError{"SOCKS5 代理握手或认证失败"},
		&upstreamError{"HTTPS 代理证书或 TLS 握手验证失败"},
		&probeError{kind: probeInvalidContent},
		&probeError{kind: probeInvalidIP},
		errors.New("unknown protocol failure"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			candidate := recoveredRoute("", failure)
			h := newRecoveryHarness(t, func(int) (route, error) { return candidate, nil })
			h.trigger()
			tick := h.clock.next(t, 2*time.Second)
			close(tick.release)
			st := waitRecoveryState(t, h.s, "blocked")
			if h.calls.Load() != 2 || candidate.closed.Load() != 1 || !strings.Contains(st.Reason, "需手动") {
				t.Fatalf("hard failure retried or leaked candidate: %+v calls=%d closed=%d", st, h.calls.Load(), candidate.closed.Load())
			}
		})
	}
}

func TestRecoveryRequiresPriorActiveIntentAndRejectsInitialIPMismatch(t *testing.T) {
	for _, operation := range []string{"check", "failed-arm", "active-ip-mismatch", "strict-health"} {
		t.Run(operation, func(t *testing.T) {
			s := configured(t)
			if operation != "strict-health" {
				optInRecovery(t, s, "proxy-only")
			}
			clock := newRecoveryClock()
			s.recoveryWait = clock.wait
			var failed atomic.Bool
			r := &recoveryRoute{fp: "original-fixed-route", probe: func(context.Context) (string, error) {
				if failed.Load() {
					if operation == "active-ip-mismatch" {
						return "203.0.113.8", nil
					}
					return "", context.DeadlineExceeded
				}
				return "203.0.113.7", nil
			}}
			s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
			if operation == "active-ip-mismatch" || operation == "strict-health" {
				if e := s.Arm(context.Background()); e != nil {
					t.Fatal(e)
				}
				failed.Store(true)
				s.health(context.Background())
			} else {
				failed.Store(true)
				if operation == "check" {
					s.Check(context.Background())
				} else {
					s.Arm(context.Background())
				}
			}
			if st := s.Status(); st.State != "blocked" || s.armedIntent {
				t.Fatalf("manual or invalid session created recovery intent: %+v", st)
			}
			select {
			case <-clock.ticks:
				t.Fatal("ineligible session scheduled a retry")
			default:
			}
		})
	}
}

func TestNewRecoveryEpisodeWaitsForStaleValidatorToClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	stale := recoveredRoute("203.0.113.7", nil)
	stale.probe = func(context.Context) (string, error) { close(entered); <-release; return "203.0.113.7", nil }
	h := newRecoveryHarness(t, func(attempt int) (route, error) {
		if attempt == 1 {
			return stale, nil
		}
		r := recoveredRoute("203.0.113.7", nil)
		if attempt == 3 {
			r.probe = func(context.Context) (string, error) {
				if stale.closed.Load() != 1 {
					return "", errors.New("retry validators overlapped")
				}
				return "203.0.113.7", nil
			}
		}
		return r, nil
	})
	h.trigger()
	tick := h.clock.next(t, 2*time.Second)
	close(tick.release)
	<-entered
	h.s.Disarm()
	if e := h.s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	h.s.blockProbe(h.s.Status().SessionRevision, context.Background(), "公网出口检查失败：", context.DeadlineExceeded, "")
	if st := h.s.Status(); st.State != "recovering" {
		t.Fatal("second explicit session did not enter a fresh recovery episode")
	}
	close(release)
	tick = h.clock.next(t, 2*time.Second)
	close(tick.release)
	waitRecoveryState(t, h.s, "proxy_active")
	if h.calls.Load() != 4 || stale.closed.Load() != 1 {
		t.Fatal("stale candidate retained or unexpected overlapping attempt")
	}
}
