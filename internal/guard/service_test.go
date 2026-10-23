package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"exitguard/internal/enforce"
	"exitguard/internal/model"
)

type testRoute struct {
	ip  string
	err error
}

func (r *testRoute) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("test route has no target")
}
func (r *testRoute) Fingerprint(context.Context) (string, error)   { return "route-1", r.err }
func (r *testRoute) Probe(context.Context, string) (string, error) { return r.ip, r.err }
func (r *testRoute) Close() error                                  { return nil }
func validConfig(t *testing.T) model.Config {
	t.Helper()
	return model.Config{Mode: "clash", ExpectedIPs: []string{"203.0.113.7"}, ProxyURL: "http://127.0.0.1:7890", ClashControllerURL: "http://127.0.0.1:9090", ClashSelector: "ExitGuard", ClashNode: "Fixed", ProbeURL: "https://api.ipify.org?format=json", ProxyPort: 17890, Programs: []string{filepath.Join(t.TempDir(), "Test.exe")}}
}
func configured(t *testing.T, controls ...http.Handler) *Service {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := validConfig(t)
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c.ProxyPort = uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	if err = s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if len(controls) > 0 {
		setter, ok := any(s).(interface{ SetControlHandler(http.Handler) error })
		if !ok {
			t.Fatal("service cannot host trusted local control")
		}
		if e := setter.SetControlHandler(controls[0]); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		ready := s.listener != nil
		s.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not start")
		}
		time.Sleep(time.Millisecond)
	}
	s.makeRoute = func(model.Config, string) (route, error) { return &testRoute{ip: "203.0.113.7"}, nil }
	s.inspect = func(_ context.Context, p enforce.Policy) (enforce.Proof, error) {
		return enforce.Proof{Active: true, PolicyHash: enforce.Hash(p)}, nil
	}
	return s
}
func TestArmRequiresExpectedIPAndTargets(t *testing.T) {
	for _, field := range []string{"expected", "targets"} {
		t.Run(field, func(t *testing.T) {
			s := configured(t)
			c := s.Config()
			if field == "expected" {
				c.ExpectedIPs = nil
			} else {
				c.Programs = nil
			}
			if err := s.SaveConfig(c); err != nil {
				t.Fatal(err)
			}
			if err := s.Arm(context.Background()); err == nil {
				t.Fatal("armed with incomplete identity")
			}
			if s.Status().State == "armed" {
				t.Fatal("gate open")
			}
		})
	}
}
func TestArmRequiresMatchingOSProof(t *testing.T) {
	for _, proof := range []enforce.Proof{{}, {Active: true, PolicyHash: "wrong"}} {
		s := configured(t)
		s.inspect = func(context.Context, enforce.Policy) (enforce.Proof, error) { return proof, nil }
		if err := s.Arm(context.Background()); err == nil {
			t.Fatal("armed without matching OS proof")
		}
	}
}
func TestFailedAndUnexpectedProbeCannotArm(t *testing.T) {
	for _, r := range []*testRoute{{err: errors.New("unreachable")}, {ip: "198.51.100.1"}, {ip: "bad"}} {
		s := configured(t)
		s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
		if err := s.Arm(context.Background()); err == nil {
			t.Fatal("armed on failed public IP proof")
		}
	}
}
func TestConfigChangeDisarmsAndClosesTunnel(t *testing.T) {
	s := configured(t)
	if err := s.Arm(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	if !s.track(a, s.generation) {
		t.Fatal("armed connection denied")
	}
	c := s.Config()
	c.ExpectedIPs = []string{"198.51.100.1"}
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if s.Status().State == "armed" {
		t.Fatal("config change retained admission")
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("established tunnel remains open")
	}
}
func TestConfigPersistenceNeverArmedAndUnixPrivateMode(t *testing.T) {
	s := configured(t)
	if err := s.Arm(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	// POSIX mode bits do not attest a Windows DACL. Windows still runs the
	// persistence/admission checks below; real ACL validation is separate.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("config mode %o", info.Mode().Perm())
	}
	next, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if next.Status().State == "armed" {
		t.Fatal("persisted admission")
	}
	c := next.Config()
	c.ExpectedIPs[0] = "changed"
	if next.Config().ExpectedIPs[0] != "203.0.113.7" {
		t.Fatal("config snapshot alias mutates live policy")
	}
}
func TestConfigRejectsNetworkControllerAndEmbeddedSecrets(t *testing.T) {
	for _, raw := range []string{"http://localhost:9090", "http://192.168.1.2:9090", "http://u:p@127.0.0.1:9090", "http://127.0.0.1:9090/path?secret=x"} {
		s := configured(t)
		c := s.Config()
		c.ClashControllerURL = raw
		if err := s.SaveConfig(c); err == nil {
			t.Fatalf("accepted unsafe controller %q", raw)
		}
	}
}
func TestStaleValidationCannotRearmAfterDisarm(t *testing.T) {
	s := configured(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.inspect = func(_ context.Context, p enforce.Policy) (enforce.Proof, error) {
		once.Do(func() { close(entered); <-release })
		return enforce.Proof{Active: true, PolicyHash: enforce.Hash(p)}, nil
	}
	done := make(chan error)
	go func() { done <- s.Arm(context.Background()) }()
	<-entered
	s.Disarm()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("stale validation rearmed after explicit stop")
	}
	if s.Status().State == "armed" {
		t.Fatal("gate reopened")
	}
}

func TestCancelledCheckDoesNotRemainChecking(t *testing.T) {
	s := configured(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Check(ctx); err == nil {
		t.Fatal("cancelled check succeeded")
	}
	if s.Status().State == "checking" {
		t.Fatal("cancelled validation remains checking forever")
	}
}
func TestPortChangeRejectsWithoutAdvertisingWrongListener(t *testing.T) {
	s := configured(t)
	if err := s.Arm(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := s.Config()
	c := s.Config()
	if c.ProxyPort == 65535 {
		c.ProxyPort--
	} else {
		c.ProxyPort++
	}
	if err := s.SaveConfig(c); err == nil {
		t.Fatal("running service accepted a port that it does not own")
	}
	if s.Config().ProxyPort != before.ProxyPort || s.Status().ProxyAddress != proxyAddress(before) || s.Status().State == "armed" {
		t.Fatal("port and live listener identity diverged")
	}
}
func TestOccupiedPortCannotArm(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s, e := New(filepath.Join(t.TempDir(), "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	c := validConfig(t)
	c.ProxyPort = uint16(l.Addr().(*net.TCPAddr).Port)
	if e = s.SaveConfig(c); e != nil {
		t.Fatal(e)
	}
	if e = s.Run(context.Background()); e == nil {
		t.Fatal("occupied listener accepted")
	}
	if e = s.Arm(context.Background()); e == nil {
		t.Fatal("armed after listener failure")
	}
}
func TestListenerShutdownRevokesAdmission(t *testing.T) {
	s := configured(t)
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	l := s.listener
	s.mu.Unlock()
	l.Close()
	deadline := time.Now().Add(time.Second)
	for s.Status().State == "armed" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Status().State == "armed" {
		t.Fatal("listener exit kept gate armed")
	}
	if e := s.Arm(context.Background()); e == nil {
		t.Fatal("rearmed stopped listener")
	}
}
func TestHealthMismatchClosesOwnedTunnels(t *testing.T) {
	s := configured(t)
	if e := s.Arm(context.Background()); e != nil {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	defer b.Close()
	if !s.track(a, s.generation) {
		t.Fatal("admission rejected")
	}
	s.mu.Lock()
	s.fingerprint = "old-interface"
	s.mu.Unlock()
	s.health(context.Background())
	if s.Status().State != "blocked" {
		t.Fatal("route change not blocked")
	}
	if _, e := b.Write([]byte("x")); e == nil {
		t.Fatal("route change retained tunnel")
	}
}
func TestEventsBoundedAndSecretAbsent(t *testing.T) {
	s := configured(t)
	s.SetSecret("do-not-log-this-token")
	for i := 0; i < 150; i++ {
		s.Disarm()
	}
	events := s.Events()
	if len(events) > 100 {
		t.Fatal("unbounded events")
	}
	data, e := json.Marshal(events)
	if e != nil {
		t.Fatal(e)
	}
	config, e := os.ReadFile(s.configPath)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte("do-not-log-this-token")) || bytes.Contains(config, []byte("do-not-log-this-token")) {
		t.Fatal("secret leaked")
	}
}

type waitingRoute struct {
	testRoute
	entered chan struct{}
}

func (r *waitingRoute) Probe(ctx context.Context, _ string) (string, error) {
	close(r.entered)
	<-ctx.Done()
	return "", ctx.Err()
}
func TestDisarmCancelsInFlightProbe(t *testing.T) {
	s := configured(t)
	r := &waitingRoute{testRoute: testRoute{ip: "203.0.113.7"}, entered: make(chan struct{})}
	s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
	done := make(chan error, 1)
	go func() { done <- s.Arm(context.Background()) }()
	<-r.entered
	s.Disarm()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled arm succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Disarm left owned probe running")
	}
}

func TestConcurrentArmCannotQueuePastExplicitDisarm(t *testing.T) {
	s := configured(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.inspect = func(_ context.Context, p enforce.Policy) (enforce.Proof, error) {
		once.Do(func() { close(entered); <-release })
		return enforce.Proof{Active: true, PolicyHash: enforce.Hash(p)}, nil
	}
	first := make(chan error, 1)
	go func() { first <- s.Arm(context.Background()) }()
	<-entered
	second := make(chan error, 1)
	go func() { second <- s.Arm(context.Background()) }()
	select {
	case err := <-second:
		if err == nil {
			t.Fatal("concurrent Arm succeeded")
		}
	case <-time.After(100 * time.Millisecond):
		s.Disarm()
		close(release)
		<-first
		select {
		case err := <-second:
			if err == nil {
				t.Fatal("queued Arm reopened gate after explicit Disarm")
			}
		case <-time.After(time.Second):
			t.Fatal("queued Arm did not complete")
		}
		return
	}
	s.Disarm()
	close(release)
	<-first
}
