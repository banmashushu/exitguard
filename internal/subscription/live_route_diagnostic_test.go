//go:build exitguard_live_diagnostic

package subscription

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in, one bounded GET. The default uses the active localhost CONNECT route;
// direct and stored select an explicit direct path or the saved download path.
// No controller, settings, library or node lifecycle operation occurs.
func TestLiveDirectVersusActiveGuardRoute(t *testing.T) {
	clientIdentity := "exitguard"
	switch os.Getenv("EXITGUARD_DIAGNOSTIC_CLIENT") {
	case "", "exitguard":
	case "mihomo":
		clientIdentity = "mihomo"
	default:
		t.Fatal("diagnostic client must be a fixed supported enum")
	}

	root, e := os.UserConfigDir()
	if e != nil {
		t.Fatal("private store unavailable")
	}
	file, e := os.Open(filepath.Join(root, "ExitGuard", "config.json.subscriptions.json"))
	if e != nil {
		t.Fatal("private store unavailable")
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if e != nil || len(data) > MaxBytes {
		t.Fatal("private store unavailable")
	}
	lib, e := Decode(data)
	if e != nil {
		t.Fatal("private store invalid")
	}
	source := ""
	downloadRoute := DownloadActiveExitGuard
	useStoredRoute := false
	switch os.Getenv("EXITGUARD_DIAGNOSTIC_ROUTE") {
	case "", DownloadActiveExitGuard:
	case DownloadDirect:
		downloadRoute = DownloadDirect
	case "stored":
		useStoredRoute = true
	default:
		t.Fatal("diagnostic route must be a fixed supported enum")
	}
	count := 0
	for _, record := range lib.Records {
		if record.SourceKind == "url" {
			source = record.SourceURL
			if useStoredRoute {
				downloadRoute = record.DownloadRoute
			}
			count++
		}
	}
	if count != 1 {
		t.Fatal("diagnostic needs exactly one stored URL source")
	}
	for _, route := range []struct {
		name  string
		proxy bool
	}{{downloadRoute, downloadRoute == DownloadActiveExitGuard}} {
		started := time.Now().UTC().Format(time.RFC3339Nano)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		body, metadata, connectStatus, e := liveRouteFetch(ctx, source, route.proxy, clientIdentity)
		cancel()
		finished := time.Now().UTC().Format(time.RFC3339Nano)
		output := liveDiagnosticClassify(body)
		output["started_at_utc"], output["finished_at_utc"] = started, finished
		for key, value := range liveTrojanOptionCounts(body) {
			output[key] = value
		}
		output["download_route"], output["response"], output["fetch_failed"] = route.name, metadata, e != nil
		output["client_identity"] = clientIdentity
		if route.proxy {
			output["proxy_connect_status"], output["proxy_inactive"] = connectStatus, connectStatus == 503
		}
		encoded, _ := json.Marshal(output)
		fmt.Println(string(encoded))
	}
}

type liveRouteResponse struct {
	liveDiagnosticResponse
	ContentLength    int64  `json:"content_length"`
	TransferEncoding string `json:"transfer_encoding"`
	Uncompressed     bool   `json:"uncompressed"`
}

func liveRouteFetch(ctx context.Context, source string, throughGuard bool, clientIdentity string) ([]byte, liveRouteResponse, int, error) {
	meta := liveRouteResponse{liveDiagnosticResponse: liveDiagnosticResponse{ContentType: "absent"}, ContentLength: -1, TransferEncoding: "absent"}
	agent := ""
	switch clientIdentity {
	case "exitguard":
		agent = "ExitGuard/0.2.2"
	case "mihomo":
		agent = "clash.meta/v1.19.33"
	default:
		return nil, meta, 0, ErrDownload
	}
	var connectStatus atomic.Int32
	if validateDownloadURL(source) != nil {
		return nil, meta, int(connectStatus.Load()), ErrDownload
	}
	parsed, _ := url.Parse(source)
	host, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		port = "443"
	}
	pinned := ""
	if ip, e := netip.ParseAddr(host); e == nil {
		if !PublicIPv4(ip) {
			return nil, meta, int(connectStatus.Load()), ErrDownload
		}
		pinned = ip.String()
	} else {
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if e != nil || len(ips) == 0 || len(ips) > 32 {
			return nil, meta, int(connectStatus.Load()), ErrDownload
		}
		for _, candidate := range ips {
			ip, ok := netip.AddrFromSlice(candidate)
			if !ok || !PublicIPv4(ip.Unmap()) {
				return nil, meta, int(connectStatus.Load()), ErrDownload
			}
			if pinned == "" {
				pinned = ip.Unmap().String()
			}
		}
	}
	target := net.JoinHostPort(pinned, port)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
		if !strings.EqualFold(address, net.JoinHostPort(host, port)) {
			return nil, ErrDownload
		}
		if !throughGuard {
			return dialer.DialContext(ctx, "tcp4", target)
		}
		connection, e := dialer.DialContext(ctx, "tcp4", "127.0.0.1:17890")
		if e != nil {
			return nil, ErrDownload
		}
		ok := false
		defer func() {
			if !ok {
				connection.Close()
			}
		}()
		stop := context.AfterFunc(ctx, func() { connection.Close() })
		defer stop()
		deadline := time.Now().Add(5 * time.Second)
		if end, exists := ctx.Deadline(); exists && end.Before(deadline) {
			deadline = end
		}
		if connection.SetDeadline(deadline) != nil {
			return nil, ErrDownload
		}
		// The source path/query and its token appear only after HTTPS starts below.
		if _, e = fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); e != nil {
			return nil, ErrDownload
		}
		reader := bufio.NewReaderSize(connection, 4096)
		var header strings.Builder
		for {
			line, e := reader.ReadSlice('\n')
			if e != nil || header.Len()+len(line) > 32<<10 {
				return nil, ErrDownload
			}
			header.Write(line)
			if string(line) == "\r\n" {
				break
			}
		}
		response, e := http.ReadResponse(bufio.NewReader(strings.NewReader(header.String())), &http.Request{Method: "CONNECT"})
		if e != nil {
			return nil, ErrDownload
		}
		connectStatus.Store(int32(response.StatusCode))
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, ErrDownload
		}
		if ctx.Err() != nil {
			return nil, ErrDownload
		}
		if connection.SetDeadline(time.Time{}) != nil {
			return nil, ErrDownload
		}
		ok = true
		return &liveRouteBufferedConn{Conn: connection, reader: reader}, nil
	}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, "GET", source, nil)
	if e != nil {
		return nil, meta, int(connectStatus.Load()), ErrDownload
	}
	// No added Accept/encoding; the only optional identity is the exact bundled core.
	request.Header.Set("User-Agent", agent)
	response, e := client.Do(request)
	if e != nil {
		return nil, meta, int(connectStatus.Load()), ErrDownload
	}
	defer response.Body.Close()
	meta.Status = response.StatusCode
	meta.ContentLength, meta.Uncompressed = response.ContentLength, response.Uncompressed
	switch {
	case len(response.TransferEncoding) == 0:
		meta.TransferEncoding = "absent"
	case len(response.TransferEncoding) == 1 && strings.EqualFold(response.TransferEncoding[0], "chunked"):
		meta.TransferEncoding = "chunked"
	default:
		meta.TransferEncoding = "other"
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(response.Header.Get("Content-Type"), ";", 2)[0]))
	switch contentType {
	case "text/plain", "text/html", "application/yaml", "text/yaml", "application/x-yaml", "application/json", "application/octet-stream":
		meta.ContentType = contentType
	case "":
	default:
		meta.ContentType = "other"
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	meta.BodyBytes = len(body)
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	meta.HTML = strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") || strings.Contains(lower, "<html") && strings.Contains(lower, "<body")
	if e != nil || len(body) > MaxBytes || response.StatusCode != 200 {
		return nil, meta, int(connectStatus.Load()), ErrDownload
	}
	return body, meta, int(connectStatus.Load()), nil
}

type liveRouteBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *liveRouteBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Only fixed public option names and enumerated booleans/transports leave memory.
func liveTrojanOptionCounts(content []byte) map[string]any {
	raw := strings.TrimSpace(string(content))
	if decoded, e := decode64(raw); e == nil && strings.Contains(string(decoded), "://") {
		raw = string(decoded)
	}
	known := map[string]bool{}
	for _, key := range []string{"allowInsecure", "allow_insecure", "skip-cert-verify", "skipCertVerify", "peer", "sni", "type", "fast-open", "fast_open", "tfo", "udp-relay", "udp_relay", "udpRelay", "udp", "udp-relay-mode", "udp_relay_mode", "udpRelayMode", "tls", "security", "host", "path", "alpn", "fp", "pcs", "mux", "flow", "packetEncoding", "packet-encoding", "obfs", "plugin", "serviceName", "headerType", "aid", "alterId", "encryption", "verify", "insecure", "remarks", "group"} {
		known[key] = true
	}
	keys, flags, names, transports := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	booleans := map[string]map[string]int{}
	for _, line := range strings.Split(raw, "\n") {
		u, e := url.Parse(strings.TrimSpace(line))
		if e != nil || !strings.EqualFold(u.Scheme, "trojan") {
			continue
		}
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil {
			continue
		}
		for key := range q {
			if known[key] {
				keys[key]++
			} else {
				keys["other_key"]++
			}
		}
		for _, key := range []string{"allowInsecure", "fast-open", "fast_open", "tfo", "udp-relay", "udp_relay", "udpRelay", "udp", "mux", "skip-cert-verify"} {
			if values, exists := q[key]; exists {
				category := "invalid"
				if len(values) == 1 {
					switch strings.ToLower(values[0]) {
					case "false", "0":
						category = "false"
					case "true", "1":
						category = "true"
					}
				}
				if booleans[key] == nil {
					booleans[key] = map[string]int{}
				}
				booleans[key][category]++
			}
		}
		if value, exists := q["allowInsecure"]; exists {
			if len(value) != 1 {
				flags["invalid"]++
			} else {
				switch strings.ToLower(value[0]) {
				case "0", "false":
					flags["false"]++
				case "1", "true":
					flags["true"]++
				default:
					flags["invalid"]++
				}
			}
		}
		peer, sni := q.Get("peer"), q.Get("sni")
		switch {
		case peer != "" && sni != "" && strings.EqualFold(peer, sni):
			names["both_match"]++
		case peer != "" && sni != "":
			names["both_differ"]++
		case peer != "" || sni != "":
			names["one_present"]++
		default:
			names["none"]++
		}
		switch q.Get("type") {
		case "tcp":
			transports["tcp"]++
		case "ws":
			transports["ws"]++
		case "grpc":
			transports["grpc"]++
		case "http":
			transports["http"]++
		case "h2":
			transports["h2"]++
		case "httpupgrade":
			transports["httpupgrade"]++
		case "xhttp":
			transports["xhttp"]++
		case "quic":
			transports["quic"]++
		case "":
			transports["absent"]++
		default:
			transports["other"]++
		}
	}
	return map[string]any{"trojan_recognized_option_keys": keys, "allowInsecure_boolean_counts": flags, "option_boolean_counts": booleans, "peer_sni_relation": names, "transport_type_counts": transports}
}
