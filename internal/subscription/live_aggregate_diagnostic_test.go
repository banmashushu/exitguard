//go:build exitguard_live_diagnostic

package subscription

import (
	"bytes"
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
	"testing"
	"time"
)

// TestLiveAggregateDiagnostic is deliberately opt-in. It reads the sole stored
// URL only in memory, makes at most two requests, and prints fixed classifications
// and counts. No URL, response text, label, endpoint, option value or credential
// is printed or written. It neither imports content nor starts any proxy node.
func TestLiveAggregateDiagnostic(t *testing.T) {
	root, e := os.UserConfigDir()
	if e != nil {
		t.Fatal("private store unavailable")
	}
	f, e := os.Open(filepath.Join(root, "ExitGuard", "config.json.subscriptions.json"))
	if e != nil {
		t.Fatal("private store unavailable")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil || len(data) > MaxBytes {
		t.Fatal("private store unavailable")
	}
	lib, e := Decode(data)
	if e != nil {
		t.Fatal("private store invalid")
	}
	source := ""
	count := 0
	for _, record := range lib.Records {
		if record.SourceKind == "url" {
			count++
			source = record.SourceURL
		}
	}
	if count != 1 {
		t.Fatal("diagnostic needs exactly one stored URL source")
	}
	// Pinned upstream config/config.go: GlobalUA = "clash.meta/" + C.Version.
	for _, agent := range []struct{ label, ua string }{{"bundled_core_explicit_text", "clash.meta/v1.19.33"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		body, meta, e := liveDiagnosticFetch(ctx, source, agent.ua)
		cancel()
		output := liveDiagnosticClassify(body)
		output["agent"], output["response"], output["fetch_failed"] = agent.label, meta, e != nil
		encoded, _ := json.Marshal(output)
		fmt.Println(string(encoded))
	}
}

type liveDiagnosticResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	BodyBytes   int    `json:"body_bytes"`
	HTML        bool   `json:"html_marker"`
}

// Mirrors the production Fetch trust boundary, but never follows redirects so
// the entire opt-in comparison cannot exceed two HTTP requests.
func liveDiagnosticFetch(ctx context.Context, source, agent string) ([]byte, liveDiagnosticResponse, error) {
	meta := liveDiagnosticResponse{ContentType: "absent"}
	if validateDownloadURL(source) != nil {
		return nil, meta, ErrDownload
	}
	u, _ := url.Parse(source)
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	pinned := ""
	if ip, e := netip.ParseAddr(host); e == nil {
		if !PublicIPv4(ip) {
			return nil, meta, ErrDownload
		}
		pinned = ip.String()
	} else {
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if e != nil || len(ips) == 0 || len(ips) > 32 {
			return nil, meta, ErrDownload
		}
		for _, candidate := range ips {
			ip, ok := netip.AddrFromSlice(candidate)
			if !ok || !PublicIPv4(ip.Unmap()) {
				return nil, meta, ErrDownload
			}
			if pinned == "" {
				pinned = ip.Unmap().String()
			}
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if !strings.EqualFold(address, net.JoinHostPort(host, port)) {
			return nil, ErrDownload
		}
		return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(pinned, port))
	}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", source, nil)
	if e != nil {
		return nil, meta, ErrDownload
	}
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "identity")
	resp, e := client.Do(req)
	if e != nil {
		return nil, meta, ErrDownload
	}
	defer resp.Body.Close()
	meta.Status = resp.StatusCode
	mime := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	switch mime {
	case "text/plain", "text/html", "application/yaml", "text/yaml", "application/x-yaml", "application/json", "application/octet-stream":
		meta.ContentType = mime
	case "":
	default:
		meta.ContentType = "other"
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	meta.BodyBytes = len(body)
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	meta.HTML = strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") || strings.Contains(lower, "<html") && strings.Contains(lower, "<body")
	if e != nil || len(body) > MaxBytes || resp.StatusCode != 200 {
		return nil, meta, ErrDownload
	}
	return body, meta, nil
}

func liveDiagnosticClassify(content []byte) map[string]any {
	raw := strings.TrimSpace(strings.TrimPrefix(string(content), "\ufeff"))
	format := "other"
	if raw == "" {
		format = "empty_or_whitespace"
	} else if decoded, e := decode64(raw); e == nil && bytes.Contains(decoded, []byte("://")) {
		raw = strings.TrimSpace(string(decoded))
		format = "base64_uri"
	} else if bytes.Contains(content, []byte("proxies:")) {
		format = "yaml_candidate"
	} else if json.Valid(content) {
		format = "json"
	} else {
		first := strings.SplitN(raw, "\n", 2)[0]
		if at := strings.Index(first, "://"); at > 0 && at < 20 && !strings.ContainsAny(first[:at], " {}[]\t") {
			format = "uri_candidate"
		}
	}
	schemes, keys, reject := map[string]int{}, map[string]int{}, map[string]int{}
	known, current := map[string]bool{}, map[string]bool{}
	for _, key := range []string{"type", "security", "sni", "host", "path", "serviceName", "flow", "fp", "alpn", "encryption", "headerType", "pbk", "sid", "spx", "allowInsecure", "insecure", "peer", "plugin", "obfs", "obfs-password", "password", "udp", "congestion_control", "udp_relay_mode", "packetEncoding", "packet-encoding", "mode", "eh", "ed", "remarks", "group", "tls", "psk", "protocol", "obfsParam", "protocolParam"} {
		known[key] = true
	}
	for _, key := range []string{"type", "security", "sni", "host", "path", "serviceName", "flow", "fp", "alpn", "encryption"} {
		current[key] = true
	}
	lines := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines++
		u, e := url.Parse(line)
		if e != nil {
			schemes["unparseable"]++
			reject["url_parse"]++
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "http", "https", "socks5", "socks", "anytls":
			schemes[scheme]++
		default:
			schemes["other"]++
		}
		q, e := url.ParseQuery(u.RawQuery)
		if e != nil {
			reject["query_parse"]++
			continue
		}
		unknown := false
		for key, values := range q {
			if known[key] {
				keys[key]++
			} else {
				keys["unrecognized_key"]++
			}
			if len(values) != 1 {
				reject["duplicate_query_key"]++
			}
			if !current[key] {
				unknown = true
			}
		}
		m, e := uriNode(line)
		if e == nil {
			if _, e = canonicalNode(m); e == nil {
				reject["accepted"]++
			} else {
				reject["canonical_node"]++
			}
			continue
		}
		switch {
		case unknown:
			reject["uri_query_key_allowlist"]++
		case scheme != "ss" && scheme != "vmess" && scheme != "vless" && scheme != "trojan" && scheme != "http" && scheme != "https" && scheme != "socks5":
			reject["uri_scheme_allowlist"]++
		case u.User == nil || u.Hostname() == "" || u.Port() == "":
			reject["uri_endpoint_or_userinfo"]++
		case u.Path != "" && u.Path != "/":
			reject["uri_path"]++
		case scheme == "ss" && len(q) != 0:
			reject["ss_query_options"]++
		case scheme == "vmess":
			reject["vmess_payload"]++
		case (scheme == "vless" || scheme == "trojan") && q.Get("type") != "ws" && (q.Get("path") != "" || q.Get("host") != ""):
			reject["unused_transport_options"]++
		case scheme == "vless" || scheme == "trojan":
			reject["uri_security_or_transport_policy"]++
		default:
			reject["uri_other"]++
		}
	}
	nodes, e := Parse(content)
	supported := 0
	nodeTypes := map[string]int{}
	if e == nil {
		for _, n := range nodes {
			nodeTypes[safeType(n.Type)]++
			if n.Supported {
				supported++
			}
		}
	}
	return map[string]any{"fetched_bytes": len(content), "trimmed_bytes": len(strings.TrimSpace(string(content))), "format": format, "nonempty_lines": lines, "schemes": schemes, "recognized_query_key_counts": keys, "parser_classification": reject, "parsed_nodes": len(nodes), "supported_nodes": supported, "parsed_node_types": nodeTypes}
}
