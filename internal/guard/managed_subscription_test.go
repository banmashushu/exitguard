package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"exitguard/internal/managedproxy"
	"exitguard/internal/model"
	"exitguard/internal/subscription"
)

const safeSubscriptionFixture = "proxies: [{name: Selected, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: subscription-private-password}]"

func importedManagedProfile(t *testing.T, s *Service) (model.SubscriptionSummary, model.RemoteProfile) {
	t.Helper()
	summary, e := s.ImportSubscription(context.Background(), model.SubscriptionInput{Name: "Own", Content: []byte(safeSubscriptionFixture)})
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := s.SubscriptionNodes(summary.ID)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.SaveRemoteProfile(model.RemoteProfileInput{Name: "Fixed final", ProxyURL: "http://fixed.example:8080", ExpectedIPs: []string{"203.0.113.7"}, CredentialAction: "replace", Username: "fixed-account-private", Password: "fixed-password-private", ManagedSubscriptionID: summary.ID, ManagedNodeID: nodes[0].ID})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SelectRemoteProfile(p.ID); e != nil {
		t.Fatal(e)
	}
	return summary, p
}
func TestManagedSubscriptionStoreProfileAndFailureRetention(t *testing.T) {
	s := profileService(t)
	summary, p := importedManagedProfile(t, s)
	if s.Config().ProxyURL != "http://fixed.example:8080" || s.proxyUsername != "fixed-account-private" || s.Config().ExpectedIPs[0] != "203.0.113.7" {
		t.Fatal("subscription changed fixed final identity")
	}
	raw, e := os.ReadFile(s.configPath + ".profiles.json")
	if e != nil {
		t.Fatal(e)
	}
	var version struct{ Version int }
	json.Unmarshal(raw, &version)
	if version.Version != 3 {
		t.Fatal("managed reference lacks fail-closed format version")
	}
	if e = s.DeleteSubscription(summary.ID); e == nil {
		t.Fatal("referenced subscription deleted")
	}
	s.status.State, s.armedIntent = "proxy_active", true
	before := s.Status().SessionRevision
	if _, e = s.ImportSubscription(context.Background(), model.SubscriptionInput{ID: summary.ID, Name: "Own", Content: []byte("broken-private-source")}); e == nil {
		t.Fatal("broken update accepted")
	}
	if s.Status().State != "proxy_active" || s.Status().SessionRevision != before {
		t.Fatal("failed candidate disturbed active snapshot")
	}
	lease := newFakeManagedLease()
	s.managedLease = lease
	if _, e = s.ImportSubscription(context.Background(), model.SubscriptionInput{ID: summary.ID, Name: "Own", Content: []byte(strings.Replace(safeSubscriptionFixture, "Selected", "Renamed", 1))}); e != nil {
		t.Fatal(e)
	}
	if lease.Valid() || activeState(s.Status().State) || s.armedIntent || s.Config().ManagedNodeID != p.ManagedNodeID {
		t.Fatal("successful refresh lost immutable choice or kept old core")
	}
	restored, e := New(s.configPath)
	if e != nil || restored.Config().ManagedSubscriptionID != summary.ID || restored.proxyPassword != "fixed-password-private" || activeState(restored.Status().State) {
		t.Fatal("restart lost fixed pair or activated core", e)
	}
	summaries, _ := s.Subscriptions()
	nodes, _ := s.SubscriptionNodes(summary.ID)
	public, _ := json.Marshal([]any{s.Config(), s.Status(), s.Events(), summaries, nodes, p})
	for _, secret := range []string{"subscription-private-password", "fixed-account-private", "fixed-password-private", "node.example"} {
		if strings.Contains(string(public), secret) {
			t.Fatal("public subscription snapshot exposed connection data")
		}
	}
	cfg := s.Config()
	cfg.ManagedNodeID = strings.Repeat("a", 64)
	if e = s.SaveConfig(cfg); e == nil {
		t.Fatal("advanced settings replaced managed selection")
	}
}

type fakeManagedLease struct {
	url, user, password, identity string
	valid                         atomic.Bool
	done                          chan struct{}
	once                          sync.Once
	stopBlock                     chan struct{}
}

func newFakeManagedLease() *fakeManagedLease {
	l := &fakeManagedLease{url: "http://127.0.0.1:17891", user: "generated-user-private", password: "generated-password-private", identity: "selected-node/pinned-node/core-pinned", done: make(chan struct{})}
	l.valid.Store(true)
	return l
}
func (l *fakeManagedLease) Settings() (string, string, string, string) {
	return l.url, l.user, l.password, l.identity
}
func (l *fakeManagedLease) Valid() bool           { return l.valid.Load() }
func (l *fakeManagedLease) Done() <-chan struct{} { return l.done }
func (l *fakeManagedLease) Revoke()               { l.once.Do(func() { l.valid.Store(false); close(l.done) }) }
func (l *fakeManagedLease) Stop() error {
	l.once.Do(func() { l.valid.Store(false); close(l.done) })
	if l.stopBlock != nil {
		<-l.stopBlock
	}
	return nil
}

type fakeManagedController struct {
	lease             *fakeManagedLease
	ensures, currents atomic.Int32
	ensureFn          func(context.Context, subscription.Node) (managedLease, error)
}

func (c *fakeManagedController) Ensure(ctx context.Context, node subscription.Node) (managedLease, error) {
	c.ensures.Add(1)
	if c.ensureFn != nil {
		return c.ensureFn(ctx, node)
	}
	return c.lease, nil
}
func (c *fakeManagedController) Current(string) (managedLease, error) {
	c.currents.Add(1)
	if !c.lease.Valid() {
		return nil, errors.New("unavailable")
	}
	return c.lease, nil
}
func (c *fakeManagedController) CoreIdentity() string { return "core-pinned" }
func TestManagedManualLaunchRecoveryReuseAndUnexpectedDeath(t *testing.T) {
	s := profileService(t)
	_, _ = importedManagedProfile(t, s)
	controller := &fakeManagedController{lease: newFakeManagedLease()}
	s.managed = controller
	s.makeChainedRemoteRoute = func(_ context.Context, c model.Config, user, password, preUser, prePassword string) (route, error) {
		if c.ProxyURL != "http://fixed.example:8080" || user != "fixed-account-private" || preUser != "generated-user-private" || c.ManagedNodeID != "" {
			t.Fatal("managed handoff changed final route or crossed credentials")
		}
		return &testRoute{ip: "203.0.113.7"}, nil
	}
	if _, e := s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "", true); e == nil || controller.ensures.Load() != 0 {
		t.Fatal("core launched without owned guard listener")
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	s.running, s.listener, s.boundPort = true, listener, s.Config().ProxyPort
	r, e := s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "", true)
	if e != nil {
		t.Fatal(e)
	}
	s.activeRoute = r
	s.status.State = "proxy_active"
	fp, e := r.Fingerprint(context.Background())
	if e != nil || !strings.Contains(fp, "core-pinned") {
		t.Fatal("core identity absent from route fingerprint")
	}
	next, e := s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "")
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
	if controller.ensures.Load() != 1 || controller.currents.Load() != 1 {
		t.Fatal("automatic reuse launched another core")
	}
	controller.lease.Stop()
	waitRecoveryState(t, s, "blocked")
	if _, e = s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", ""); e == nil || controller.ensures.Load() != 1 {
		t.Fatal("dead core was restarted automatically")
	}
}
func TestManagedStopDoesNotWaitUnderServiceMutex(t *testing.T) {
	s := profileService(t)
	_, _ = importedManagedProfile(t, s)
	l := newFakeManagedLease()
	l.stopBlock = make(chan struct{})
	s.managedLease = l
	done := make(chan struct{})
	go func() { s.Disarm(); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("pause waited for process under service mutex")
	}
	_ = s.Status()
	close(l.stopBlock)
}
func TestManagedDeathDuringCheckingRevokesBeforeAdmission(t *testing.T) {
	s := profileService(t)
	_, _ = importedManagedProfile(t, s)
	controller := &fakeManagedController{lease: newFakeManagedLease()}
	s.managed = controller
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s.running, s.listener, s.boundPort = true, l, s.Config().ProxyPort
	s.status.State = "checking"
	s.makeChainedRemoteRoute = func(context.Context, model.Config, string, string, string, string) (route, error) {
		return &testRoute{ip: "203.0.113.7"}, nil
	}
	r, e := s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "", true)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	controller.lease.Stop()
	waitRecoveryState(t, s, "blocked")
}
func TestManagedClosedCandidateDoesNotRetainExitWatcher(t *testing.T) {
	s := profileService(t)
	_, _ = importedManagedProfile(t, s)
	controller := &fakeManagedController{lease: newFakeManagedLease()}
	s.managed = controller
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s.running, s.listener, s.boundPort = true, l, s.Config().ProxyPort
	s.status.State = "checking"
	s.makeChainedRemoteRoute = func(context.Context, model.Config, string, string, string, string) (route, error) {
		return &testRoute{ip: "203.0.113.7"}, nil
	}
	r, e := s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "", true)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	select {
	case <-r.(*managedRoute).watchExited:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("closed candidate retained watcher")
	}
	controller.lease.Stop()
	if s.Status().State != "checking" {
		t.Fatal("closed candidate exit watcher changed session")
	}
}
func TestManagedFailedFinalRouteConstructionStopsStartedLease(t *testing.T) {
	s := profileService(t)
	_, _ = importedManagedProfile(t, s)
	controller := &fakeManagedController{lease: newFakeManagedLease()}
	s.managed = controller
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s.running, s.listener, s.boundPort = true, l, s.Config().ProxyPort
	s.makeChainedRemoteRoute = func(context.Context, model.Config, string, string, string, string) (route, error) {
		return nil, errors.New("final unavailable")
	}
	if _, e = s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "", true); e == nil || controller.lease.Valid() {
		t.Fatal("failed final setup left owned core running")
	}
}
func TestManagedUpdateNeverSelectsAnotherNode(t *testing.T) {
	s := profileService(t)
	summary, p := importedManagedProfile(t, s)
	if _, e := s.ImportSubscription(context.Background(), model.SubscriptionInput{ID: summary.ID, Name: summary.Name, Content: []byte(strings.Replace(safeSubscriptionFixture, "subscription-private-password", "different-private-password", 1))}); e != nil {
		t.Fatal(e)
	}
	if s.Config().ManagedNodeID != p.ManagedNodeID {
		t.Fatal("refresh silently replaced selected node")
	}
	controller := &fakeManagedController{lease: newFakeManagedLease()}
	s.managed = controller
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s.running, s.listener, s.boundPort = true, l, s.Config().ProxyPort
	if _, e = s.routeFor(context.Background(), s.Config(), "", s.proxyUsername, s.proxyPassword, "", "", true); e == nil || controller.ensures.Load() != 0 {
		t.Fatal("missing immutable selection fell back to another node")
	}
}

func TestManagedPauseImmediatelyRecheckWaitsForOnlyOldLease(t *testing.T) {
	s := profileService(t)
	_, _ = importedManagedProfile(t, s)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	s.running, s.listener, s.boundPort = true, listener, s.Config().ProxyPort
	old, next := newFakeManagedLease(), newFakeManagedLease()
	next.identity = "new-owned-runtime/core-pinned"
	gate := make(chan struct{})
	old.stopBlock = gate
	ensuring := make(chan struct{})
	controller := &fakeManagedController{lease: old}
	controller.ensureFn = func(ctx context.Context, _ subscription.Node) (managedLease, error) {
		if old.Valid() {
			return old, nil
		}
		select {
		case <-ensuring:
		default:
			close(ensuring)
		}
		select {
		case <-gate:
			return next, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.managed = controller
	s.makeChainedRemoteRoute = func(context.Context, model.Config, string, string, string, string) (route, error) {
		return &testRoute{ip: "203.0.113.7"}, nil
	}
	if e = s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.Disarm()
	if old.Valid() {
		t.Fatal("pause did not synchronously revoke the old lease")
	}
	checked := make(chan error, 1)
	go func() { checked <- s.Check(context.Background()) }()
	<-ensuring
	if s.Status().State != "checking" {
		t.Fatal("startup waited with service mutex held")
	}
	close(gate)
	if e = <-checked; e != nil {
		t.Fatal(e)
	}
	if s.Status().State != "proxy_ready" || !next.Valid() {
		t.Fatal("stale lease stop/exit revoked new check")
	}
	s.Disarm()
}
func TestManagedProfileV1V2ReadsDoNotRewrite(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := profileService(t)
			extra := ""
			if version == 2 {
				extra = `,"preProxyURL":"","preProxyUsername":"","preProxyPassword":""`
			}
			raw := fmt.Sprintf(`{"version":%d,"profiles":[{"id":"0123456789abcdef0123456789abcdef","name":"Old","proxyURL":"http://fixed.example:8080","expectedIPs":[],"username":"","password":""%s}]}`, version, extra)
			if e := writeCredentialFile(s.configPath+".profiles.json", []byte(raw)); e != nil {
				t.Fatal(e)
			}
			profiles, e := s.RemoteProfiles()
			if e != nil || len(profiles) != 1 || profiles[0].ManagedSubscriptionID != "" {
				t.Fatal("old profile rejected", e)
			}
			after, e := os.ReadFile(s.configPath + ".profiles.json")
			if e != nil || string(after) != raw {
				t.Fatal("read rewrote old store")
			}
		})
	}
}
func TestManagedRuntimeErrorsRemainSafeAndActionable(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{{managedproxy.ErrPackage, "校验"}, {managedproxy.ErrNode, "节点"}, {managedproxy.ErrReadiness, "就绪"}, {managedproxy.ErrUnavailable, "手动"}, {errors.New("private-source-token"), "手动"}} {
		failure := safeProbeError(safeManagedError(test.err))
		if !strings.Contains(failure.Error(), test.want) || strings.Contains(failure.Error(), "private-source-token") || transientRecoveryFailure(failure) {
			t.Fatal("managed runtime error lost safe actionable classification")
		}
	}
}

func TestSubscriptionResponseFailuresKeepPrivateSnapshotAndActiveRoute(t *testing.T) {
	s := profileService(t)
	s.fetchSubscription = func(context.Context, string) ([]byte, error) { return []byte(safeSubscriptionFixture), nil }
	summary, e := s.ImportSubscription(context.Background(), model.SubscriptionInput{Name: "Fictitious", URL: "https://example.com/private-source"})
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := s.SubscriptionNodes(summary.ID)
	if e != nil {
		t.Fatal(e)
	}
	profile, e := s.SaveRemoteProfile(model.RemoteProfileInput{Name: "Fixed", ProxyURL: "http://fixed.example:8080", ExpectedIPs: []string{"203.0.113.7"}, CredentialAction: "clear", ManagedSubscriptionID: summary.ID, ManagedNodeID: nodes[0].ID})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SelectRemoteProfile(profile.ID); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(s.configPath + ".subscriptions.json")
	if e != nil {
		t.Fatal(e)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	revision := s.Status().SessionRevision
	lease := newFakeManagedLease()
	s.managedLease = lease
	for _, test := range []struct {
		body  string
		known error
	}{{" \r\n", subscription.ErrEmptyResponse}, {"This client is not allowed to fetch subscription", subscription.ErrClientDenied}, {"error://subscription\n<html>private-response-marker</html>", subscription.ErrContent}} {
		s.fetchSubscription = func(context.Context, string) ([]byte, error) { return []byte(test.body), nil }
		if _, e = s.RefreshSubscription(context.Background(), summary.ID); !errors.Is(e, test.known) {
			t.Fatal("refresh lost the safe source failure category")
		}
		after, e := os.ReadFile(s.configPath + ".subscriptions.json")
		if e != nil || string(after) != string(before) || s.Status().SessionRevision != revision || s.Status().State != "proxy_active" || !lease.Valid() || !s.armedIntent {
			t.Fatal("invalid response replaced private snapshot or disturbed active route")
		}
	}
}
