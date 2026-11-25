package managedproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func officialBundle(t *testing.T) bundle {
	t.Helper()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("official fixture currently staged for darwin/arm64")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(root, ".work/managed-core/darwin-arm64/mihomo")
	if _, err = os.Stat(core); err != nil {
		t.Skip("run scripts/fetch-managed-core.py before official-core smoke")
	}
	if verifyCore(core, coreHash()) != nil {
		t.Fatal("official core fixture hash differs")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "mihomo")
	data, err := os.ReadFile(core)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, data, 0755); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "exitguard-proxy-supervisor")
	build := exec.Command("go", "build", "-trimpath", "-o", helper, "./cmd/exitguard-proxy-supervisor")
	build.Dir = root
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v %s", err, output)
	}
	return bundle{helper, target, coreHash()}
}
func localFixtureManager(t *testing.T, b bundle) *Manager {
	t.Helper()
	m := NewManager(Options{RuntimeDir: filepath.Join(t.TempDir(), "runtime")})
	m.resolve = func() (bundle, error) { return b, nil }
	m.endpoint = func(context.Context, string) (string, error) { return "127.0.0.1", nil }
	t.Cleanup(func() { _ = m.Stop() })
	return m
}
func fixtureNode(port int) Node {
	c := map[string]any{"type": "http", "server": "selected-node.invalid", "port": port, "udp": false, "username": "node-fixture", "password": "node-fixture-secret"}
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return Node{hex.EncodeToString(h[:]), c}
}
func fixtureConnectProxy(t *testing.T, username, password, target string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != target {
			http.Error(w, "closed", 403)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)) {
			http.Error(w, "auth", 407)
			return
		}
		out, err := net.DialTimeout("tcp", target, time.Second)
		if err != nil {
			http.Error(w, "closed", 502)
			return
		}
		defer out.Close()
		conn, br, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		hits.Add(1)
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { _, _ = io.Copy(out, br) }()
		_, _ = io.Copy(conn, out)
	}))
	t.Cleanup(s.Close)
	return s
}
func connectThrough(t *testing.T, c net.Conn, target, user, pass string) *bufio.Reader {
	t.Helper()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	br := bufio.NewReader(c)
	r, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 {
		t.Fatalf("CONNECT: %d", r.StatusCode)
	}
	return br
}
func TestOfficialCorePrivateLeafAndLifetime(t *testing.T) {
	b := officialBundle(t)
	var nodeHits, finalHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "controlled-origin") }))
	defer origin.Close()
	final := fixtureConnectProxy(t, "final-fixture", "final-fixture-secret", strings.TrimPrefix(origin.URL, "http://"), &finalHits)
	front := fixtureConnectProxy(t, "node-fixture", "node-fixture-secret", strings.TrimPrefix(final.URL, "http://"), &nodeHits)
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(front.URL, "http://"))
	var port int
	fmt.Sscan(p, &port)
	n := fixtureNode(port)
	m := localFixtureManager(t, b)
	l, err := m.Ensure(context.Background(), n)
	if err != nil {
		t.Fatalf("start pinned official core: %v", err)
	}
	if !l.Valid() || !strings.Contains(l.Identity, "127.0.0.1/") || !strings.Contains(l.Identity, coreHash()) {
		t.Fatal("missing attested identity")
	}
	if nodeHits.Load() != 0 {
		t.Fatal("readiness dialed node")
	}
	c, err := net.Dial("tcp", strings.TrimPrefix(l.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_ = connectThrough(t, c, strings.TrimPrefix(final.URL, "http://"), l.Username, l.Password)
	br := connectThrough(t, c, strings.TrimPrefix(origin.URL, "http://"), "final-fixture", "final-fixture-secret")
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: controlled.invalid\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "controlled-origin" || nodeHits.Load() != 1 || finalHits.Load() != 1 {
		t.Fatal("selected node/fixed-final chain was bypassed")
	}
	current, err := m.Current(n.Identity)
	if err != nil || current != l {
		t.Fatal("exact Current did not reuse")
	}
	if _, err = m.Current(strings.Repeat("0", 64)); err == nil {
		t.Fatal("Current substituted identity")
	}
	entries, err := os.ReadDir(l.runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "config.json" && e.Name() != "cache.db" {
			t.Fatalf("unexpected bootstrap asset %s", e.Name())
		}
	}
	if err = l.Stop(); err != nil {
		t.Fatal(err)
	}
	if l.Valid() {
		t.Fatal("stopped lease live")
	}
	select {
	case <-l.Done():
	default:
		t.Fatal("Done not closed")
	}
	if _, err = os.Stat(l.runtime); !os.IsNotExist(err) {
		t.Fatal("private runtime was not removed")
	}
}
func TestOfficialCoreHelperDeathInvalidatesAndKillsOwnedGroup(t *testing.T) {
	b := officialBundle(t)
	m := localFixtureManager(t, b)
	n := fixtureNode(12345)
	l, err := m.Ensure(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("helper death did not invalidate")
	}
	if _, err = m.Current(n.Identity); err == nil {
		t.Fatal("Current restarted dead lease")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", strings.TrimPrefix(l.URL, "http://"), 50*time.Millisecond)
		if e != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("helper death orphaned listener")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func TestPublicIPv4RejectsPrivateAndSpecialSpace(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "100.64.1.1", "169.254.1.1", "198.18.0.1", "192.0.2.1", "::1", "224.1.1.1"} {
		if _, e := resolveEndpoint(context.Background(), host); e == nil {
			t.Fatalf("accepted nonpublic %s", host)
		}
	}
	if got, e := resolveEndpoint(context.Background(), "8.8.8.8"); e != nil || got != "8.8.8.8" {
		t.Fatal("public literal rejected")
	}
}

// This is a test-only parent executable. Production has no environment resolver.
func TestManagedParentFixture(t *testing.T) {
	if os.Getenv("EXITGUARD_TEST_PARENT") != "1" {
		return
	}
	b := bundle{os.Getenv("EXITGUARD_TEST_HELPER"), os.Getenv("EXITGUARD_TEST_CORE"), coreHash()}
	m := NewManager(Options{RuntimeDir: os.Getenv("EXITGUARD_TEST_RUNTIME")})
	m.resolve = func() (bundle, error) { return b, nil }
	m.endpoint = func(context.Context, string) (string, error) { return "127.0.0.1", nil }
	l, err := m.Ensure(context.Background(), fixtureNode(12345))
	if err != nil {
		fmt.Println("ERROR")
		os.Exit(3)
	}
	fmt.Println(l.URL)
	select {}
}
func TestOfficialCoreParentCrashClosesOwnedLifetimePipe(t *testing.T) {
	b := officialBundle(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestManagedParentFixture$")
	dir := filepath.Join(t.TempDir(), "runtime")
	cmd.Env = append(os.Environ(), "EXITGUARD_TEST_PARENT=1", "EXITGUARD_TEST_HELPER="+b.supervisor, "EXITGUARD_TEST_CORE="+b.core, "EXITGUARD_TEST_RUNTIME="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()
	line := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(stdout)
		if scan.Scan() {
			line <- scan.Text()
		} else {
			line <- ""
		}
	}()
	var listener string
	select {
	case listener = <-line:
	case <-time.After(12 * time.Second):
		t.Fatal("parent never became ready")
	}
	if !strings.HasPrefix(listener, "http://127.0.0.1:") {
		t.Fatal("parent startup failed")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(4 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", strings.TrimPrefix(listener, "http://"), 50*time.Millisecond)
		if e != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("parent crash left core running")
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("parent crash left private runtime")
	}
}

func TestOfficialCoreWrongNodeAuthAndTLSStayClosed(t *testing.T) {
	b := officialBundle(t)
	for _, mode := range []string{"auth", "tls"} {
		t.Run(mode, func(t *testing.T) {
			var leafHits atomic.Int32
			final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("failed node reached final destination") }))
			defer final.Close()
			leaf := fixtureConnectProxy(t, "node-fixture", "node-fixture-secret", strings.TrimPrefix(final.URL, "http://"), &leafHits)
			sni := make(chan string, 4)
			if mode == "tls" {
				tlsLeaf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS was accepted") }))
				tlsLeaf.Config.ErrorLog = log.New(io.Discard, "", 0)
				tlsLeaf.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
					select {
					case sni <- h.ServerName:
					default:
					}
					return nil, nil
				}}
				tlsLeaf.StartTLS()
				defer tlsLeaf.Close()
				leaf = tlsLeaf
			}
			_, p, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(leaf.URL, "http://"), "https://"))
			var port int
			fmt.Sscan(p, &port)
			n := fixtureNode(port)
			if mode == "auth" {
				n.Config["password"] = "wrong-fixture-secret"
			} else {
				n.Config["tls"] = true
				n.Config["sni"] = "explicit-authority.invalid"
			}
			data, _ := json.Marshal(n.Config)
			h := sha256.Sum256(data)
			n.Identity = hex.EncodeToString(h[:])
			m := localFixtureManager(t, b)
			l, err := m.Ensure(context.Background(), n)
			if err != nil {
				t.Fatal(err)
			}
			c, err := net.Dial("tcp", strings.TrimPrefix(l.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			target := strings.TrimPrefix(final.URL, "http://")
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, base64.StdEncoding.EncodeToString([]byte(l.Username+":"+l.Password)))
			_, _ = io.ReadAll(io.LimitReader(c, 4096))
			if leafHits.Load() != 0 {
				t.Fatal("bad credentials reached authenticated leaf")
			}
			if mode == "tls" {
				select {
				case got := <-sni:
					if got != "explicit-authority.invalid" {
						t.Fatalf("TLS hostname changed: %q", got)
					}
				case <-time.After(time.Second):
					t.Fatal("pinned hostname did not reach local TLS fixture")
				}
			}
		})
	}
}
func TestOfficialCoreHashTamperingRejectedBeforeLaunch(t *testing.T) {
	b := officialBundle(t)
	f, err := os.OpenFile(b.core, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("tamper"))
	f.Close()
	m := localFixtureManager(t, b)
	if _, err = m.Ensure(context.Background(), fixtureNode(12345)); err != ErrPackage {
		t.Fatalf("tampered core accepted: %v", err)
	}
	if _, err = m.Current(fixtureNode(12345).Identity); err == nil {
		t.Fatal("tampered core created a lease")
	}
}

func TestOfficialCoreChildExitInvalidatesLease(t *testing.T) {
	b := officialBundle(t)
	m := localFixtureManager(t, b)
	n := fixtureNode(12345)
	l, err := m.Ensure(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	// Query only the child of this test's owned helper, never external instances.
	output, err := exec.Command("/usr/bin/pgrep", "-P", itoa(l.process.Process.Pid)).Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 1 {
		t.Fatal("owned helper did not have exactly one core")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	command, err := exec.Command("/bin/ps", "-p", itoa(pid), "-o", "comm=").Output()
	if err != nil || strings.TrimSpace(string(command)) != b.core {
		t.Fatal("child does not match exact test core path")
	}
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("core exit did not revoke lease")
	}
	if _, err = m.Current(n.Identity); err == nil {
		t.Fatal("Current restarted exited core")
	}
	if err = l.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestOfficialCoreSelectionAndIndependentManagersStayIsolated(t *testing.T) {
	b := officialBundle(t)
	m := localFixtureManager(t, b)
	other := localFixtureManager(t, b)
	first := fixtureNode(12345)
	l1, err := m.Ensure(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	independent, err := other.Ensure(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := fixtureNode(12346)
	l2, err := m.Ensure(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if l1.Valid() || l1.runtime == l2.runtime || l2.runtime == independent.runtime {
		t.Fatal("selection shared a process/runtime")
	}
	if err = l1.Stop(); err != nil {
		t.Fatal(err)
	}
	if !l2.Valid() || !independent.Valid() {
		t.Fatal("stale cleanup stopped a different owned process")
	}
	if err = m.Stop(); err != nil {
		t.Fatal(err)
	}
	if !independent.Valid() {
		t.Fatal("manager stopped independent instance")
	}
}

func TestOfficialCoreRevokePreventsSameNodeReuse(t *testing.T) {
	b := officialBundle(t)
	m := localFixtureManager(t, b)
	n := fixtureNode(12345)
	old, err := m.Ensure(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	old.Revoke()
	if old.Valid() {
		t.Fatal("Revoke left live lease")
	}
	select {
	case <-old.Done():
	default:
		t.Fatal("Revoke did not signal immediately")
	}
	replacement, err := m.Ensure(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == old || replacement.runtime == old.runtime {
		t.Fatal("Ensure reused revoked runtime")
	}
	if err = old.Stop(); err != nil {
		t.Fatal(err)
	}
	if !replacement.Valid() {
		t.Fatal("late exact cleanup killed replacement")
	}
}
