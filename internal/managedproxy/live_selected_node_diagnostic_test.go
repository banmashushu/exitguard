//go:build exitguard_live_diagnostic

package managedproxy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"exitguard/internal/subscription"
)

// TestLiveCurrentSelectedNodeConnectivity is an explicit, one-execution live
// diagnostic. No source URL is fetched, no private store is written, and no
// other process/OS network settings are controlled. All output is fixed metadata.
func TestLiveCurrentSelectedNodeConnectivity(t *testing.T) {
	if os.Getenv("EXITGUARD_LIVE_SELECTED_NODE") != "1" {
		t.Skip("explicit diagnostic opt-in required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("diagnostic_config_location")
	}
	configPath := filepath.Join(home, "Library", "Application Support", "ExitGuard", "config.json")
	config, err := selectedDiagnosticRead(configPath, 1<<20)
	if err != nil {
		t.Fatal("diagnostic_config_read")
	}
	var selection struct {
		SubscriptionID string `json:"managedSubscriptionID"`
		NodeID         string `json:"managedNodeID"`
	}
	if json.Unmarshal(config, &selection) != nil || selection.SubscriptionID == "" || selection.NodeID == "" {
		t.Fatal("diagnostic_selection_missing")
	}
	data, err := selectedDiagnosticRead(configPath+".subscriptions.json", subscription.MaxBytes)
	if err != nil {
		t.Fatal("diagnostic_library_read")
	}
	lib, err := subscription.Decode(data)
	if err != nil {
		t.Fatal("diagnostic_library_invalid")
	}
	selected, err := lib.Node(selection.SubscriptionID, selection.NodeID)
	if err != nil {
		t.Fatal("diagnostic_selected_node_unavailable")
	}
	runSelectedNodeDiagnostic(t, selected)
}

// TestLiveRemainingEligibleNodes permits only the two remaining observed
// ordinary candidates. The expected snapshot hash is read-only metadata, never
// a credential/source URL, and is supplied explicitly for this single batch.
func TestLiveRemainingEligibleNodes(t *testing.T) {
	if os.Getenv("EXITGUARD_LIVE_REMAINING_NODES") != "1" {
		t.Skip("explicit diagnostic opt-in required")
	}
	expectedHash := os.Getenv("EXITGUARD_DIAGNOSTIC_SNAPSHOT_SHA256")
	if len(expectedHash) != 64 || strings.ToLower(expectedHash) != expectedHash {
		t.Fatal("diagnostic_snapshot_selector")
	}
	if decoded, err := hex.DecodeString(expectedHash); err != nil || len(decoded) != sha256.Size {
		t.Fatal("diagnostic_snapshot_selector")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("diagnostic_config_location")
	}
	path := filepath.Join(home, "Library", "Application Support", "ExitGuard", "config.json.subscriptions.json")
	data, err := selectedDiagnosticRead(path, subscription.MaxBytes)
	if err != nil {
		t.Fatal("diagnostic_library_read")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expectedHash {
		t.Fatal("diagnostic_snapshot_changed")
	}
	lib, err := subscription.Decode(data)
	if err != nil || len(lib.Records) != 1 || len(lib.Records[0].Nodes) != 35 {
		t.Fatal("diagnostic_snapshot_counts")
	}
	var eligible []subscription.Node
	for _, node := range lib.Records[0].Nodes {
		if node.Supported {
			eligible = append(eligible, node)
		}
	}
	if len(eligible) != 4 {
		t.Fatal("diagnostic_snapshot_counts")
	}
	selectedDiagnosticOutput(t, map[string]any{"stage": "snapshot", "hash_matches": true, "record_count": 1, "node_count": 35, "eligible_count": 4})
	for _, index := range []int{2, 3} {
		label := "candidate_3"
		if index == 3 {
			label = "candidate_4"
		}
		t.Run(label, func(t *testing.T) { runSelectedNodeDiagnostic(t, eligible[index]) })
	}
}

func runSelectedNodeDiagnostic(t *testing.T, selected subscription.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	manager := NewManager(Options{RuntimeDir: filepath.Join(t.TempDir(), "owned")})
	// This test-only package seam changes only bundle location. Endpoint
	// resolution remains the normal public-IPv4 resolver, and official core
	// bytes retain the manifest SHA verification.
	manager.resolve = func() (bundle, error) {
		root := "/Applications/ExitGuard.app/Contents/Helpers"
		return bundle{filepath.Join(root, "exitguard-proxy-supervisor"), filepath.Join(root, "mihomo"), coreHash()}, nil
	}
	var owned *Lease
	defer func() {
		stopped := manager.Stop() == nil
		removed := true
		if owned != nil {
			_, err := os.Stat(owned.runtime)
			removed = os.IsNotExist(err)
		}
		selectedDiagnosticOutput(t, map[string]any{"stage": "cleanup", "success": stopped, "runtime_removed": removed})
	}()
	started := time.Now()
	lease, err := manager.Ensure(ctx, Node{Identity: selected.ID, Config: selected.Config})
	owned = lease
	if err != nil {
		selectedDiagnosticOutput(t, map[string]any{"stage": "core_start", "success": false, "error": selectedDiagnosticError(err), "elapsed_ms": time.Since(started).Milliseconds()})
		return
	}
	selectedDiagnosticOutput(t, map[string]any{"stage": "core_start", "success": lease.Valid(), "elapsed_ms": time.Since(started).Milliseconds()})
	logs := selectedDiagnosticLogs(ctx, lease)
	defer logs.stop()
	logs.phase("https_probe")
	selectedDiagnosticHTTPS(t, ctx, lease)
	if ctx.Err() == nil {
		logs.phase("fixed_greeting")
		selectedDiagnosticGreeting(t, ctx, lease)
	}
	logs.stop()
	selectedDiagnosticOutput(t, map[string]any{"stage": "core_logs", "attached": logs.attached, "fixed_counts": logs.snapshot()})
}

func selectedDiagnosticRead(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("diagnostic_read")
	}
	return data, nil
}

func selectedDiagnosticOutput(t *testing.T, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("diagnostic_output")
	}
	t.Log(string(data))
}

func selectedDiagnosticError(err error) string {
	if err == nil {
		return "none"
	}
	for _, known := range []struct {
		err  error
		code string
	}{{ErrNode, "node"}, {ErrPackage, "package"}, {ErrStorage, "storage"}, {ErrReadiness, "readiness"}, {ErrStart, "start"}, {ErrUnavailable, "unavailable"}} {
		if errors.Is(err, known.err) {
			return known.code
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "eof"
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	var cert *x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &hostname) {
		return "x509"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "transport"
}

func selectedDiagnosticHTTPS(t *testing.T, parent context.Context, lease *Lease) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	proxy, err := url.Parse(lease.URL)
	if err != nil {
		t.Fatal("diagnostic_owned_proxy")
	}
	proxy.User = url.UserPassword(lease.Username, lease.Password)
	ownedAddress := proxy.Host
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != ownedAddress {
				return nil, ErrUnavailable
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		t.Fatal("diagnostic_request")
	}
	response, err := client.Do(request)
	status := 0
	valid := false
	if response != nil {
		status = response.StatusCode
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
		response.Body.Close()
		if err == nil {
			err = readErr
		}
		if len(body) <= 1024 && readErr == nil {
			ip, parseErr := netip.ParseAddr(strings.TrimSpace(string(body)))
			valid = parseErr == nil && subscription.PublicIPv4(ip)
		}
	}
	selectedDiagnosticOutput(t, map[string]any{"stage": "https_probe", "success": err == nil && status == 200 && valid, "status": status, "public_ipv4_valid": valid, "error": selectedDiagnosticError(err), "elapsed_ms": time.Since(started).Milliseconds()})
}

func selectedDiagnosticGreeting(t *testing.T, parent context.Context, lease *Lease) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	result := map[string]any{"stage": "fixed_greeting", "connect_status": 0, "valid_method": false, "error": "none"}
	defer func() { result["elapsed_ms"] = time.Since(started).Milliseconds(); selectedDiagnosticOutput(t, result) }()
	proxy, err := url.Parse(lease.URL)
	if err != nil {
		t.Fatal("diagnostic_owned_proxy")
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", proxy.Host)
	if err != nil {
		result["error"] = selectedDiagnosticError(err)
		return
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	connection.SetDeadline(deadline)
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: "130.12.42.140:443"}, Host: "130.12.42.140:443", Header: make(http.Header)}
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(lease.Username+":"+lease.Password)))
	if err = request.Write(connection); err != nil {
		result["error"] = selectedDiagnosticError(err)
		return
	}
	reader := bufio.NewReaderSize(connection, 32<<10)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		result["error"] = selectedDiagnosticError(err)
		return
	}
	result["connect_status"] = response.StatusCode
	if response.StatusCode != 200 {
		result["error"] = "connect_refused"
		return
	}
	if _, err = connection.Write([]byte{5, 1, 2}); err != nil {
		result["error"] = selectedDiagnosticError(err)
		return
	}
	var method [2]byte
	if _, err = io.ReadFull(reader, method[:]); err != nil {
		result["error"] = selectedDiagnosticError(err)
		return
	}
	result["valid_method"] = method[0] == 5 && method[1] == 2
	if result["valid_method"] != true {
		result["error"] = "method_refused"
	}
}

type selectedLogDiagnostic struct {
	mu         sync.Mutex
	stage      string
	counts     map[string]map[string]int
	attached   bool
	connection net.Conn
	done       chan struct{}
	once       sync.Once
}

func selectedDiagnosticLogs(ctx context.Context, lease *Lease) *selectedLogDiagnostic {
	out := &selectedLogDiagnostic{stage: "setup", counts: map[string]map[string]int{}, done: make(chan struct{})}
	data, err := selectedDiagnosticRead(filepath.Join(lease.runtime, "config.json"), 128<<10)
	var cfg struct {
		Controller string `json:"external-controller"`
		Secret     string `json:"secret"`
	}
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		close(out.done)
		return out
	}
	host, _, err := net.SplitHostPort(cfg.Controller)
	if err != nil || host != "127.0.0.1" || cfg.Secret == "" {
		close(out.done)
		return out
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", cfg.Controller)
	if err != nil {
		close(out.done)
		return out
	}
	deadline, _ := ctx.Deadline()
	// Optional log attachment must not consume the actual probe's budget.
	handshakeDeadline := time.Now().Add(time.Second)
	if deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}
	connection.SetDeadline(handshakeDeadline)
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+cfg.Controller+"/logs?level=debug", nil)
	const key = "MDEyMzQ1Njc4OWFiY2RlZg=="
	request.Header.Set("Authorization", "Bearer "+cfg.Secret)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Key", key)
	request.Header.Set("Sec-WebSocket-Version", "13")
	reader := bufio.NewReader(io.LimitReader(connection, 128<<10))
	if err = request.Write(connection); err != nil {
		connection.Close()
		close(out.done)
		return out
	}
	response, err := http.ReadResponse(reader, request)
	accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if err != nil || response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(accept[:]) {
		connection.Close()
		close(out.done)
		return out
	}
	out.connection, out.attached = connection, true
	connection.SetDeadline(deadline)
	go func() {
		defer close(out.done)
		for count := 0; count < 64; count++ {
			var prefix [2]byte
			if _, err := io.ReadFull(reader, prefix[:]); err != nil {
				return
			}
			if prefix[1]&128 != 0 || prefix[0]&15 == 8 {
				return
			}
			size := uint64(prefix[1] & 127)
			if size == 126 {
				var extended [2]byte
				if _, err := io.ReadFull(reader, extended[:]); err != nil {
					return
				}
				size = uint64(binary.BigEndian.Uint16(extended[:]))
			} else if size == 127 {
				var extended [8]byte
				if _, err := io.ReadFull(reader, extended[:]); err != nil {
					return
				}
				size = binary.BigEndian.Uint64(extended[:])
			}
			if size > 16<<10 {
				return
			}
			payload := make([]byte, int(size))
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
			if prefix[0]&15 != 1 {
				continue
			}
			var event struct {
				Type    string `json:"type"`
				Payload string `json:"payload"`
			}
			if json.Unmarshal(payload, &event) != nil {
				continue
			}
			// Raw private events are never retained or output. Classification is
			// a fixed substring hint, not a claim of verified failure origin.
			category := selectedDiagnosticLogCategory(event.Payload)
			out.mu.Lock()
			if out.counts[out.stage] == nil {
				out.counts[out.stage] = map[string]int{}
			}
			out.counts[out.stage][category]++
			out.mu.Unlock()
		}
	}()
	return out
}
func (l *selectedLogDiagnostic) phase(stage string) { l.mu.Lock(); l.stage = stage; l.mu.Unlock() }
func (l *selectedLogDiagnostic) stop() {
	l.once.Do(func() {
		if l.connection != nil {
			l.connection.Close()
		}
		<-l.done
	})
}
func (l *selectedLogDiagnostic) snapshot() map[string]map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]map[string]int{}
	for stage, counts := range l.counts {
		out[stage] = map[string]int{}
		for category, count := range counts {
			out[stage][category] = count
		}
	}
	return out
}

// Specific failure hints take precedence over generic "dial" in the same event.
// These labels describe matched messages only, not a verified failure origin.
func selectedDiagnosticLogCategory(payload string) string {
	text := strings.ToLower(payload)
	for _, category := range []struct {
		code  string
		hints []string
	}{
		{"expired", []string{"certificate has expired", "certificate expired", "certificate is expired"}},
		{"unknownca", []string{"unknown authority", "unknown ca", "unknown certificate authority"}},
		{"certificate", []string{"x509", "certificate"}},
		{"auth", []string{"authentication", "auth failed", "unauthorized", "invalid password", "wrong password", "password mismatch"}},
		{"refused", []string{"connection refused", "actively refused"}},
		{"timeout", []string{"timeout", "timed out", "deadline exceeded"}},
		{"eof", []string{"eof"}},
		{"dns", []string{"no such host", "dns", "lookup "}},
		{"network", []string{"network is unreachable", "network unreachable", "no route to host"}},
		{"local_socket", []string{"broken pipe", "closed pipe", "use of closed network connection", "bad file descriptor", "socket is not connected"}},
		{"dial", []string{"dial"}},
	} {
		for _, hint := range category.hints {
			if strings.Contains(text, hint) {
				return category.code
			}
		}
	}
	return "other"
}
