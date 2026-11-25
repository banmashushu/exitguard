// Package managedproxy owns a private, dedicated proxy core. It never controls
// another proxy installation, modifies system settings, or selects a route.
package managedproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNode        = errors.New("managed_proxy_node")
	ErrPackage     = errors.New("managed_proxy_package")
	ErrStorage     = errors.New("managed_proxy_storage")
	ErrStart       = errors.New("managed_proxy_start")
	ErrReadiness   = errors.New("managed_proxy_readiness")
	ErrUnavailable = errors.New("managed_proxy_unavailable")
)

// Node contains a single canonical validated subscription leaf, never a root
// configuration. Identity is the SHA-256 of its canonical JSON encoding.
type Node struct {
	Identity string
	Config   map[string]any
}

// Options deliberately has no executable path or environment override.
type Options struct{ RuntimeDir string }

func DefaultOptions(configPath string) Options { return Options{RuntimeDir: configPath + ".managed"} }

type Manager struct {
	op       sync.Mutex
	mu       sync.Mutex
	opts     Options
	lease    *Lease
	resolve  func() (bundle, error)
	endpoint func(context.Context, string) (string, error)
}

func NewManager(opts Options) *Manager {
	return &Manager{opts: opts, resolve: resolveBundle, endpoint: resolveEndpoint}
}
func (m *Manager) CoreIdentity() string { return coreIdentity() }

type Lease struct {
	URL, Username, Password, Identity string
	valid                             atomic.Bool
	ready                             atomic.Bool
	done                              chan struct{}
	once                              sync.Once
	life                              *os.File
	process                           *exec.Cmd
	exited                            chan struct{}
	runtime                           string
	nodeIdentity                      string
}

func (l *Lease) Valid() bool { return l != nil && l.valid.Load() && l.ready.Load() }
func (l *Lease) Done() <-chan struct{} {
	if l == nil {
		c := make(chan struct{})
		close(c)
		return c
	}
	return l.done
}
func (l *Lease) invalidate() {
	l.once.Do(func() { l.valid.Store(false); close(l.done); _ = l.life.Close() })
}

// Revoke invalidates this lease immediately and closes its lifetime pipe. It
// never waits for a process and is safe while the service revokes its route.
func (l *Lease) Revoke() {
	if l != nil {
		l.invalidate()
	}
}

// Current only reuses a live exact lease. It never launches or recovers a core.
func (m *Manager) Current(identity string) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease == nil || m.lease.nodeIdentity != identity || !m.lease.Valid() {
		return nil, ErrUnavailable
	}
	return m.lease, nil
}
func (m *Manager) Stop() error {
	m.op.Lock()
	defer m.op.Unlock()
	return m.stop()
}
func (m *Manager) stop() error {
	m.mu.Lock()
	l := m.lease
	m.lease = nil
	m.mu.Unlock()
	if l == nil {
		return nil
	}
	err := l.Stop()
	if err != nil {
		m.mu.Lock()
		if m.lease == nil {
			m.lease = l
		}
		m.mu.Unlock()
	}
	return err
}

// Stop revokes and stops only this lease, even if its manager has since selected another node.
func (l *Lease) Stop() error {
	if l == nil {
		return nil
	}
	l.invalidate()
	select {
	case <-l.exited:
	case <-time.After(4 * time.Second):
		terminateOwned(l.process)
		select {
		case <-l.exited:
		case <-time.After(time.Second):
			return ErrStart
		}
	}
	return nil
}

// Ensure is permitted only during an explicit check/start. A cancelled startup
// leaves no live process. Successful leases live until Stop or process death.
func (m *Manager) Ensure(ctx context.Context, n Node) (*Lease, error) {
	m.op.Lock()
	defer m.op.Unlock()
	if err := validateNode(n); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrStart
	}
	if l, err := m.Current(n.Identity); err == nil {
		return l, nil
	}
	if err := m.stop(); err != nil {
		return nil, err
	}
	pinned, err := m.endpoint(ctx, n.Config["server"].(string))
	if err != nil {
		return nil, ErrNode
	}
	b, err := m.resolve()
	if err != nil {
		return nil, ErrPackage
	}
	if err = verifyBundle(b); err != nil {
		return nil, err
	}
	dir, err := newRuntimeDirectory(m.opts.RuntimeDir)
	if err != nil {
		return nil, ErrStorage
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()
	port, err := unusedPort()
	if err != nil {
		return nil, ErrStart
	}
	controller, err := unusedPort()
	if err != nil || controller == port {
		return nil, ErrStart
	}
	user, pass, secret := randomToken(), randomToken(), randomToken()
	if user == "" || pass == "" || secret == "" {
		return nil, ErrStart
	}
	data, err := generateConfig(n, pinned, port, controller, user, pass, secret)
	if err != nil {
		return nil, err
	}
	if err = writePrivate(filepath.Join(dir, "config.json"), data); err != nil {
		return nil, ErrStorage
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, ErrStart
	}
	defer read.Close()
	cmd := exec.Command(b.supervisor, "--runtime", dir)
	cmd.Stdin = read
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = childEnvironment(dir)
	cmd.Dir = dir
	configureOwned(cmd)
	if err = cmd.Start(); err != nil {
		write.Close()
		return nil, ErrStart
	}
	l := &Lease{URL: "http://127.0.0.1:" + itoa(port), Username: user, Password: pass, Identity: n.Identity + "/" + pinned + "/" + m.CoreIdentity(), nodeIdentity: n.Identity, done: make(chan struct{}), life: write, process: cmd, exited: make(chan struct{}), runtime: dir}
	l.valid.Store(true)
	m.mu.Lock()
	m.lease = l
	m.mu.Unlock()
	go func() { _ = cmd.Wait(); l.invalidate(); terminateOwned(cmd); _ = os.RemoveAll(dir); close(l.exited) }()
	readyCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if !waitReady(readyCtx, l, controller, secret, n) {
		l.invalidate()
		_ = m.stop()
		return nil, ErrReadiness
	}
	l.ready.Store(true)
	cleanup = false
	return l, nil
}
func unusedPort() (int, error) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func randomToken() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func waitReady(ctx context.Context, l *Lease, port int, secret string, n Node) bool {
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext, DisableKeepAlives: true}, Timeout: 500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		if attestController(ctx, client, port, secret, n) && attestListener(ctx, client, l) {
			return l.valid.Load()
		}
		select {
		case <-ctx.Done():
			return false
		case <-l.Done():
			return false
		case <-ticker.C:
		}
	}
}
