package managedproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testNode() Node {
	c := map[string]any{"type": "http", "server": "fixture.example", "port": 12345, "udp": false, "username": "node-user", "password": "node-password"}
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return Node{Identity: hex.EncodeToString(h[:]), Config: c}
}
func TestUnavailableManagerNeverStartsFromCurrent(t *testing.T) {
	m := NewManager(DefaultOptions(filepath.Join(t.TempDir(), "config.json")))
	if _, err := m.Current(testNode().Identity); err == nil {
		t.Fatal("missing lease accepted")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
}
func TestGeneratedConfigPinsSingleLeafAndAuthentication(t *testing.T) {
	n := testNode()
	data, err := generateConfig(n, "8.8.8.8", 34567, 34568, "proxy-user", "proxy-password", "controller-secret-123456789")
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c["external-controller"] != "127.0.0.1:34568" || c["secret"] != "controller-secret-123456789" {
		t.Fatal("controller is not authenticated loopback")
	}
	l := c["listeners"].([]any)
	listener := l[0].(map[string]any)
	if len(l) != 1 || listener["listen"] != "127.0.0.1" || listener["proxy"] != leafName || listener["type"] != "http" {
		t.Fatalf("bad listener: %v", listener)
	}
	if strings.Contains(string(data), "DIRECT") || c["proxy-groups"] != nil || c["proxy-providers"] != nil || c["tun"] != nil {
		t.Fatal("unrequested routes or system settings")
	}
	if err = validateRuntimeConfig(data); err != nil {
		t.Fatal(err)
	}
}
func TestRuntimeRejectsInjectedNodeSettingsAndIdentity(t *testing.T) {
	for _, key := range []string{"dialer-proxy", "interface-name", "skip-cert-verify", "plugin", "providers", "certificate", "private-key", "proxy-groups", "name"} {
		n := testNode()
		n.Config[key] = "private-secret"
		if _, err := generateConfig(n, "8.8.8.8", 34567, 34568, "u", "p", "s"); err == nil {
			t.Fatalf("accepted %s", key)
		} else if strings.Contains(err.Error(), "private-secret") {
			t.Fatal("secret in error")
		}
	}
	n := testNode()
	n.Identity = strings.Repeat("0", 64)
	if _, err := generateConfig(n, "8.8.8.8", 34567, 34568, "u", "p", "s"); err == nil {
		t.Fatal("accepted mismatched identity")
	}
	n = testNode()
	n.Config["ws-opts"] = map[string]any{"path": "/", "headers": map[string]any{"Host": "ok.example", "inject": "x"}}
	if _, err := generateConfig(n, "8.8.8.8", 34567, 34568, "u", "p", "s"); err == nil {
		t.Fatal("accepted unsupported transport for http")
	}
}
func TestMinimalEnvironmentExcludesInheritedHooksAndInjection(t *testing.T) {
	t.Setenv("CLASH_POST_UP", "private-hook")
	t.Setenv("CLASH_POST_DOWN", "private-hook")
	t.Setenv("HTTP_PROXY", "private-proxy")
	t.Setenv("DYLD_INSERT_LIBRARIES", "private-inject")
	t.Setenv("GODEBUG", "private-debug")
	got := strings.Join(childEnvironment(t.TempDir()), "\n")
	for _, v := range []string{"private-hook", "private-proxy", "private-inject", "private-debug"} {
		if strings.Contains(got, v) {
			t.Fatal("inherited unsafe environment")
		}
	}
}
func TestEnsureRejectsBeforeLaunchingAndReturnsSafeError(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(Options{RuntimeDir: dir})
	n := testNode()
	n.Config["plugin"] = "private-secret"
	_, err := m.Ensure(context.Background(), n)
	if err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("unsafe validation")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("invalid node created runtime state")
	}
	if !errors.Is(err, ErrNode) {
		t.Fatal("missing safe stage code")
	}
}

func TestCancelledEnsureDoesNotReuseLiveLease(t *testing.T) {
	n := testNode()
	m := NewManager(DefaultOptions(filepath.Join(t.TempDir(), "config.json")))
	l := &Lease{nodeIdentity: n.Identity, done: make(chan struct{})}
	l.valid.Store(true)
	l.ready.Store(true)
	m.lease = l
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Ensure(ctx, n); err == nil {
		t.Fatal("cancelled startup reused a live lease")
	}
}
func TestGeneratedRootRejectsUnexpectedAndDuplicateSettings(t *testing.T) {
	good, err := generateConfig(testNode(), "8.8.8.8", 34567, 34568, "user", "pass", strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append([]byte(`{"tun":{"enable":true},`), good[1:]...),
		append([]byte(`{"geo-auto-update":true,`), good[1:]...),
		[]byte(strings.Replace(string(good), `"dns":{"enable":false}`, `"dns":{"use-hosts":false}`, 1)),
		[]byte(strings.Replace(string(good), `"store-selected":false`, `"unknown":false`, 1)),
	} {
		if validateRuntimeConfig(bad) == nil {
			t.Fatal("accepted altered root config")
		}
	}
}

func TestCurrentDoesNotPublishUnattestedStartup(t *testing.T) {
	n := testNode()
	m := NewManager(Options{})
	l := &Lease{nodeIdentity: n.Identity, done: make(chan struct{})}
	l.valid.Store(true)
	m.lease = l
	if l.Valid() {
		t.Fatal("unattested startup reported valid")
	}
	if _, err := m.Current(n.Identity); err == nil {
		t.Fatal("Current exposed a startup before listener attestation")
	}
}
