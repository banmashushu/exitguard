package guard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"exitguard/internal/model"
	"exitguard/internal/subscription"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestActiveSubscriptionDownloadRequiresRunningVerifiedRoute(t *testing.T) {
	s := profileService(t)
	direct := 0
	s.fetchSubscription = func(context.Context, string) ([]byte, error) { direct++; return []byte(safeSubscriptionFixture), nil }
	summary, e := s.ImportSubscription(context.Background(), model.SubscriptionInput{Name: "Fictitious", URL: "https://example.com/private-source"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.RefreshSubscriptionViaActive(context.Background(), summary.ID); !errors.Is(e, subscription.ErrActiveRouteUnavailable) || direct != 1 {
		t.Fatal("inactive source download fell back or changed error category")
	}
	lib, e := s.readSubscriptions()
	if e != nil || lib.Records[0].DownloadRoute != "direct" {
		t.Fatal("failed active update changed stored route")
	}
}

func TestDirectSubscriptionRefreshBootstrapsWhileFixedExitIsDown(t *testing.T) {
	s := profileService(t)
	summary := initialDirectSource(t, s)
	lib, err := s.readSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	lib.Records[0].DownloadRoute = subscription.DownloadActiveExitGuard
	if err = s.writeSubscriptions(lib); err != nil {
		t.Fatal(err)
	}
	const path = ".subscriptions.json"
	old, err := os.ReadFile(s.configPath + path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RefreshSubscription(context.Background(), summary.ID); !errors.Is(err, subscription.ErrActiveRouteUnavailable) {
		t.Fatal("fixture unexpectedly has an active exit", err)
	}
	calls := 0
	s.fetchSubscription = func(_ context.Context, source string) ([]byte, error) {
		calls++
		if source != "https://example.com/private-source" {
			t.Error("explicit refresh did not reuse its saved source")
		}
		if calls == 1 {
			return nil, subscription.ErrEmptyResponse
		}
		return []byte(strings.Replace(safeSubscriptionFixture, "Selected", "Refreshed", 1)), nil
	}
	if _, err = s.RefreshSubscriptionDirect(context.Background(), summary.ID); !errors.Is(err, subscription.ErrEmptyResponse) {
		t.Fatal("direct response was not reported", err)
	}
	unchanged, err := os.ReadFile(s.configPath + path)
	if err != nil || string(unchanged) != string(old) {
		t.Fatal("failed direct refresh overwrote the previous snapshot")
	}
	updated, err := s.RefreshSubscriptionDirect(context.Background(), summary.ID)
	if err != nil || updated.DownloadRoute != subscription.DownloadDirect || calls != 2 || activeState(s.Status().State) {
		t.Fatal("direct refresh depended on or activated the fixed exit", err)
	}
	nodes, err := s.SubscriptionNodes(summary.ID)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "Refreshed" || !nodes[0].Supported {
		t.Fatal("refreshed node did not become selectable", err)
	}
}

type subscriptionSourceTestRoute struct {
	testRoute
	fingerprint atomic.Value
	dial        func(context.Context, string, string) (net.Conn, error)
	closed      atomic.Int32
}

func (r *subscriptionSourceTestRoute) Fingerprint(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return r.fingerprint.Load().(string), nil
}
func (r *subscriptionSourceTestRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return r.dial(ctx, network, address)
}
func (r *subscriptionSourceTestRoute) Close() error { r.closed.Add(1); return nil }
func activeSubscriptionSourceFixture(t *testing.T) (*Service, *subscriptionSourceTestRoute) {
	t.Helper()
	s := profileService(t)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Disarm(); listener.Close() })
	cfg := s.Config()
	cfg.ProxyPort = uint16(listener.Addr().(*net.TCPAddr).Port)
	cfg.ExpectedIPs = []string{"203.0.113.7"}
	cfg.ProxyURL = "http://fixed.example:8080"
	if e = s.SaveConfig(cfg); e != nil {
		t.Fatal(e)
	}
	r := &subscriptionSourceTestRoute{testRoute: testRoute{ip: "203.0.113.7"}, dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no fixture dial") }}
	r.fingerprint.Store("verified-fixed-source-route")
	s.mu.Lock()
	s.running, s.listener, s.boundPort = true, listener, cfg.ProxyPort
	s.activeRoute = r
	s.fingerprint = "verified-fixed-source-route"
	s.status.State, s.status.ObservedIP = "proxy_active", "203.0.113.7"
	s.armedIntent = true
	s.mu.Unlock()
	return s, r
}
func initialDirectSource(t *testing.T, s *Service) model.SubscriptionSummary {
	t.Helper()
	s.fetchSubscription = func(context.Context, string) ([]byte, error) { return []byte(safeSubscriptionFixture), nil }
	summary, e := s.ImportSubscription(context.Background(), model.SubscriptionInput{Name: "Fictitious", URL: "https://example.com/private-source"})
	if e != nil {
		t.Fatal(e)
	}
	return summary
}
func TestActiveSourceFailurePreservesLegacyBytesAndSuccessRemembersRoute(t *testing.T) {
	s, _ := activeSubscriptionSourceFixture(t)
	summary := initialDirectSource(t, s)
	raw, e := os.ReadFile(s.configPath + ".subscriptions.json")
	if e != nil {
		t.Fatal(e)
	}
	legacy := strings.Replace(string(raw), `"version":2`, `"version":1`, 1)
	legacy = strings.Replace(legacy, `,"downloadRoute":"direct"`, "", 1)
	if e = writeCredentialFile(s.configPath+".subscriptions.json", []byte(legacy)); e != nil {
		t.Fatal(e)
	}
	activeCalls := 0
	s.fetchSubscriptionThrough = func(context.Context, string, subscription.DialContext) ([]byte, error) {
		activeCalls++
		return nil, subscription.ErrEmptyResponse
	}
	if _, e = s.RefreshSubscriptionViaActive(context.Background(), summary.ID); !errors.Is(e, subscription.ErrEmptyResponse) {
		t.Fatal("active response error lost category")
	}
	after, e := os.ReadFile(s.configPath + ".subscriptions.json")
	if e != nil || string(after) != legacy || s.Status().State != "proxy_active" {
		t.Fatal("failed active update changed legacy bytes or active route")
	}
	s.fetchSubscriptionThrough = func(context.Context, string, subscription.DialContext) ([]byte, error) {
		activeCalls++
		return []byte(safeSubscriptionFixture), nil
	}
	saved, e := s.RefreshSubscriptionViaActive(context.Background(), summary.ID)
	if e != nil || saved.DownloadRoute != "active_exitguard" {
		t.Fatal("successful explicit route was not remembered", e)
	}
	if _, e = s.RefreshSubscription(context.Background(), summary.ID); e != nil || activeCalls != 3 {
		t.Fatal("ordinary refresh did not reuse stored active route", e)
	}
	wire, e := os.ReadFile(s.configPath + ".subscriptions.json")
	if e != nil || !strings.Contains(string(wire), `"version":2`) || !strings.Contains(string(wire), `"downloadRoute":"active_exitguard"`) {
		t.Fatal("successful mutation did not upgrade library")
	}
	public, _ := json.Marshal(saved)
	if strings.Contains(string(public), "private-source") {
		t.Fatal("source escaped summary")
	}
}
func TestPauseCancelsActiveSourcePendingDial(t *testing.T) {
	s, r := activeSubscriptionSourceFixture(t)
	summary := initialDirectSource(t, s)
	before, _ := os.ReadFile(s.configPath + ".subscriptions.json")
	entered, cancelled := make(chan struct{}), make(chan struct{})
	r.dial = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	s.fetchSubscriptionThrough = func(ctx context.Context, _ string, dial subscription.DialContext) ([]byte, error) {
		_, e := dial(ctx, "tcp4", "8.8.8.8:443")
		return nil, e
	}
	done := make(chan error, 1)
	go func() { _, e := s.RefreshSubscriptionViaActive(context.Background(), summary.ID); done <- e }()
	<-entered
	s.Disarm()
	select {
	case <-cancelled:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Pause did not cancel pending source dial")
	}
	if e := <-done; !errors.Is(e, subscription.ErrActiveRouteUnavailable) {
		t.Fatal("stale source operation did not fail closed")
	}
	after, _ := os.ReadFile(s.configPath + ".subscriptions.json")
	if string(after) != string(before) {
		t.Fatal("paused source operation replaced library")
	}
}
func sourceTLSFetcher(roots *x509.CertPool, port string) func(context.Context, string, subscription.DialContext) ([]byte, error) {
	return func(ctx context.Context, raw string, dial subscription.DialContext) ([]byte, error) {
		transport := &http.Transport{Proxy: nil, DialContext: func(c context.Context, _ string, _ string) (net.Conn, error) { return dial(c, "tcp4", "8.8.8.8:"+port) }, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport}
		request, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
		request.Header.Set("User-Agent", "ExitGuard/0.2.2")
		response, e := client.Do(request)
		if e != nil {
			return nil, e
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, subscription.MaxBytes+1))
		if e != nil {
			return nil, e
		}
		if len(body) > subscription.MaxBytes {
			return nil, subscription.ErrContent
		}
		return body, nil
	}
}
func TestActiveSourceUsesTrackedTLSConnectionAndPauseClosesBody(t *testing.T) {
	s, r := activeSubscriptionSourceFixture(t)
	summary := initialDirectSource(t, s)
	before, _ := os.ReadFile(s.configPath + ".subscriptions.json")
	headers, closed := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(headers)
		<-request.Context().Done()
		close(closed)
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	r.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" || address != "8.8.8.8:"+parsed.Port() {
			t.Error("source route did not receive the pinned public endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", parsed.Host)
	}
	s.fetchSubscriptionThrough = sourceTLSFetcher(roots, parsed.Port())
	done := make(chan error, 1)
	go func() { _, e := s.RefreshSubscriptionViaActive(context.Background(), summary.ID); done <- e }()
	<-headers
	s.mu.Lock()
	tracked := len(s.connections)
	s.mu.Unlock()
	if tracked != 1 {
		t.Fatal("source socket was not owned by Pause")
	}
	paused := make(chan struct{})
	go func() { s.Disarm(); close(paused) }()
	select {
	case <-paused:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("source wrapper deadlocked Pause")
	}
	select {
	case <-closed:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Pause retained source body socket")
	}
	if e := <-done; !errors.Is(e, subscription.ErrActiveRouteUnavailable) {
		t.Fatal("paused body download was accepted")
	}
	after, _ := os.ReadFile(s.configPath + ".subscriptions.json")
	if string(after) != string(before) {
		t.Fatal("paused body response replaced old snapshot")
	}
}
func TestActiveSourceRejectsChangedGenerationPointerOrFingerprintBeforeCommit(t *testing.T) {
	for _, change := range []string{"generation", "pointer", "fingerprint"} {
		t.Run(change, func(t *testing.T) {
			s, r := activeSubscriptionSourceFixture(t)
			summary := initialDirectSource(t, s)
			before, _ := os.ReadFile(s.configPath + ".subscriptions.json")
			s.fetchSubscriptionThrough = func(context.Context, string, subscription.DialContext) ([]byte, error) {
				switch change {
				case "generation":
					s.mu.Lock()
					s.generation++
					s.mu.Unlock()
				case "pointer":
					replacement := &subscriptionSourceTestRoute{}
					replacement.fingerprint.Store("verified-fixed-source-route")
					s.mu.Lock()
					s.activeRoute = replacement
					s.mu.Unlock()
				case "fingerprint":
					r.fingerprint.Store("changed-fixed-route")
				}
				return []byte(safeSubscriptionFixture), nil
			}
			if _, e := s.RefreshSubscriptionViaActive(context.Background(), summary.ID); !errors.Is(e, subscription.ErrActiveRouteUnavailable) {
				t.Fatal("stale active route committed a source candidate")
			}
			after, _ := os.ReadFile(s.configPath + ".subscriptions.json")
			if string(after) != string(before) {
				t.Fatal("stale route changed private library")
			}
		})
	}
}
func TestActiveSourceSuccessfulManagedUpdateRevokesOwnLeaseWithoutWaiting(t *testing.T) {
	s, r := activeSubscriptionSourceFixture(t)
	summary := initialDirectSource(t, s)
	nodes, e := s.SubscriptionNodes(summary.ID)
	if e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	s.config.ManagedSubscriptionID, s.config.ManagedNodeID = summary.ID, nodes[0].ID
	s.mu.Unlock()
	lease := newFakeManagedLease()
	lease.stopBlock = make(chan struct{})
	defer close(lease.stopBlock)
	s.managedLease = lease
	s.fetchSubscriptionThrough = func(context.Context, string, subscription.DialContext) ([]byte, error) {
		return []byte(safeSubscriptionFixture), nil
	}
	done := make(chan error, 1)
	go func() { _, e := s.RefreshSubscriptionViaActive(context.Background(), summary.ID); done <- e }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("update waited for process exit under service lock")
	}
	if lease.Valid() || r.closed.Load() != 1 || activeState(s.Status().State) || s.Config().ExpectedIPs[0] != "203.0.113.7" {
		t.Fatal("successful update retained old managed route or changed fixed exit")
	}
	lib, e := s.readSubscriptions()
	if e != nil || lib.Records[0].DownloadRoute != "active_exitguard" {
		t.Fatal("successful current-subscription update failed to persist route")
	}
}

func TestActiveSourceImportsRealPinnedTLSBodyAndUntracksIt(t *testing.T) {
	s, r := activeSubscriptionSourceFixture(t)
	directCalls := 0
	s.fetchSubscription = func(context.Context, string) ([]byte, error) {
		directCalls++
		return nil, subscription.ErrEmptyResponse
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy account reached source")
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, safeSubscriptionFixture)
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	calls := 0
	r.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		if address != "8.8.8.8:"+parsed.Port() {
			t.Error("source did not use fixed public target")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", parsed.Host)
	}
	s.fetchSubscriptionThrough = sourceTLSFetcher(roots, parsed.Port())
	input := model.SubscriptionInput{Name: "Fictitious", URL: "https://example.com:" + parsed.Port() + "/private-source", DownloadRoute: "direct"}
	if _, e := s.ImportSubscription(context.Background(), input); !errors.Is(e, subscription.ErrEmptyResponse) {
		t.Fatal("direct empty result was not rejected")
	}
	input.DownloadRoute = "active_exitguard"
	saved, e := s.ImportSubscription(context.Background(), input)
	if e != nil || saved.DownloadRoute != "active_exitguard" || saved.SupportedNodeCount != 1 {
		t.Fatal("active TLS body did not import", e)
	}
	if _, e = s.RefreshSubscription(context.Background(), saved.ID); e != nil || calls != 2 || directCalls != 1 {
		t.Fatal("saved route fell back or did not reuse captured route", e)
	}
	s.mu.Lock()
	tracked, operations := len(s.connections), len(s.sourceCancels)
	same := s.activeRoute == r
	s.mu.Unlock()
	if tracked != 0 || operations != 0 || !same || s.Status().State != "proxy_active" {
		t.Fatal("source request leaked ownership or changed current route")
	}
}
