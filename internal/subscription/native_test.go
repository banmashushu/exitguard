package subscription

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"exitguard/internal/model"
	"math"
	"strings"
	"testing"
)

func TestNativeURIImportRetainsCoreFieldsAndInvalidLine(t *testing.T) {
	const uri = "trojan://fictitious-password@node.example:443?native-metadata=example#Display"
	convert := URIConverter(func(_ context.Context, lines []string) ([]URIConversion, error) {
		if len(lines) != 2 || lines[0] != uri || lines[1] != "hy2://invalid" {
			t.Fatal("native converter did not receive exact decoded URI lines")
		}
		return []URIConversion{{Config: map[string]any{"name": "Display", "type": "trojan", "server": "node.example", "port": 443, "password": "fictitious-password", "network": "ws", "ws-opts": map[string]any{"path": "/private-transport", "headers": map[string]any{"User-Agent": "native-fixed-agent", "Host": "tls.example"}}, "client-fingerprint": "random"}}, {Error: "invalid_uri"}}, nil
	})
	for _, raw := range []string{uri + "\nhy2://invalid", base64.StdEncoding.EncodeToString([]byte(uri + "\nhy2://invalid"))} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte(raw), convert)
		if err != nil || len(nodes) != 2 || !nodes[0].Supported || nodes[1].Supported || nodes[1].Type != "hysteria2" || nodes[1].Reason != ErrNodeURI.Error() {
			t.Fatal("native result or invalid placeholder lost", err)
		}
		if nodes[0].Config["client-fingerprint"] != "random" || nodes[0].Config["ws-opts"].(map[string]any)["headers"].(map[string]any)["User-Agent"] != "native-fixed-agent" {
			t.Fatal("core-native transport fields were discarded")
		}
		if ValidateCanonicalNode(nodes[0].Config) != nil {
			t.Fatal("native node cannot be persisted or handed to runtime")
		}
	}
}

func TestNativeLeafPreservesProtocolOptionsAndPrivateRoundTrip(t *testing.T) {
	fixtures := []string{
		`{name: Core, TYPE: trojan, SERVER: NODE.example, PORT: 443, password: fictitious-secret}`,
		`{name: Core, type: ss, server: node.example, port: 443, cipher: aes-128-cfb, password: fictitious-secret, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: tls.example, path: /transport, headers: {User-Agent: fixed-agent}}, udp-over-tcp: true}`,
		`{name: Core, type: ssr, server: node.example, port: 443, cipher: aes-128-cfb, password: fictitious-secret, protocol: auth_aes128_md5, obfs: tls1.2_ticket_auth, protocol-param: "2:example"}`,
		`{name: Core, type: vmess, server: node.example, port: 443, uuid: fictitious-native-uuid, alterId: 64, cipher: zero, network: h2, tls: true, h2-opts: {host: [tls.example], path: /transport}, fingerprint: pinned-certificate, client-fingerprint: random}`,
		`{name: Core, type: vless, server: node.example, port: 443, uuid: fictitious-native-uuid, network: grpc, tls: true, servername: tls.example, fingerprint: fictitious-certificate-pin, grpc-opts: {grpc-service-name: native-service, grpc-user-agent: fixed-agent}, packet-encoding: xudp}`,
		`{name: Core, type: hysteria, server: node.example, port: 443, auth-str: fictitious-secret, up: 100 Mbps, down: 100 Mbps, alpn: [hysteria]}`,
		`{name: Core, type: hysteria2, server: node.example, port: 443, password: fictitious-secret, obfs: salamander, obfs-password: fictitious-obfs, fingerprint: native-pin, initial-stream-receive-window: 8388608}`,
		`{name: Core, type: hysteria2, server: node.example, port: 443, password: fictitious-secret, future-native-counter: 9007199254740993}`,
		`{name: Core, type: tuic, server: node.example, port: 443, uuid: fictitious-native-uuid, password: fictitious-secret, congestion-controller: bbr, udp-relay-mode: native, reduce-rtt: true}`,
		`{name: Core, type: anytls, server: node.example, port: 443, password: fictitious-secret, idle-session-check-interval: 30, idle-session-timeout: 30, min-idle-session: 0}`,
		`{name: Core, type: snell, server: node.example, port: 443, psk: fictitious-secret, version: 4, obfs-opts: {mode: tls, host: tls.example}}`,
		`{name: Core, type: vless, server: node.example, port: 443, uuid: fictitious-native-uuid, network: xhttp, tls: true, xhttp-opts: {host: tls.example, path: /transport, mode: auto}, future-native-option: {padding: 42}}`,
	}
	for _, fixture := range fixtures {
		lib := Empty()
		r, err := lib.PrepareWithURIConverter(context.Background(), model.SubscriptionInput{Name: "Fictitious", Content: []byte("proxies: [" + fixture + "]")}, nil, nil)
		if err != nil || len(r.Nodes) != 1 || !r.Nodes[0].Supported {
			t.Fatal("single-endpoint native protocol option was rejected", err)
		}
		if err = lib.Put(r); err != nil {
			t.Fatal(err)
		}
		data, err := Encode(lib)
		if err != nil {
			t.Fatal("native private snapshot could not encode", err)
		}
		restored, err := Decode(data)
		if err != nil || restored.Records[0].Nodes[0].ID != r.Nodes[0].ID {
			t.Fatal("native identity changed after storage", err)
		}
		a, _ := json.Marshal(r.Nodes[0].Config)
		b, _ := json.Marshal(restored.Records[0].Nodes[0].Config)
		if string(a) != string(b) {
			t.Fatal("native effective fields changed after storage")
		}
		public, _ := json.Marshal(PublicNodes(r.Nodes))
		if strings.Contains(string(public), "fictitious-secret") || strings.Contains(string(public), "node.example") || strings.Contains(string(public), "fictitious-public-key") {
			t.Fatal("private native options leaked")
		}
	}
}

func TestNativeLeafRejectsUnicodeCoreOptionAliases(t *testing.T) {
	for _, fixture := range []struct{ key, core, value string }{
		{"ſkip-cert-verify", "skip-cert-verify", "true"},
		{"diſable-sni", "disable-sni", "true"},
		{"Private_Key", "private-key", "/tmp/fictitious-private-key"},
		{"hoſts", "hosts", "{extra.example: 8.8.8.8}"},
		{"ſecret", "secret", "fictitious-private-secret"},
	} {
		if !strings.EqualFold(strings.ReplaceAll(fixture.key, "_", "-"), fixture.core) {
			t.Fatal("fixture does not model the pinned core's option matching")
		}
		source := "proxies: [{name: 展示名称, type: trojan, server: node.example, port: 443, password: fictitious-secret, " + fixture.key + ": " + fixture.value + "}]"
		nodes, err := ParseWithURIConverter(context.Background(), []byte(source), nil)
		if err != nil || len(nodes) != 1 || nodes[0].Supported || len(nodes[0].Config) != 0 || nodes[0].Reason != ErrNodeCapability.Error() {
			t.Fatal("Unicode option alias escaped the native capability boundary", err)
		}
		if strings.Contains(nodes[0].Reason, fixture.value) {
			t.Fatal("Unicode alias rejection leaked private data")
		}
	}
	// Only literal header data is exempt from the ASCII option namespace. A
	// map-shaped value under a pretend header must not exempt nested options.
	for _, options := range []string{
		`ws-opts: {headers: {ſkip-cert-verify: {private-key: /tmp/fictitious-key}}}`,
		`future-native-option: {headers: {value: {diſable-sni: true}}}`,
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: [{name: 展示名称, type: trojan, server: node.example, port: 443, password: fictitious-secret, network: ws, "+options+"}]"), nil)
		if err != nil || len(nodes) != 1 || nodes[0].Supported {
			t.Fatal("nonliteral header namespace escaped the option audit", err)
		}
	}
}

func TestNativeLeafPreservesUnicodeValuesAndLiteralHeaderData(t *testing.T) {
	for _, source := range []string{
		`{name: 展示名称, type: trojan, server: node.example, port: 443, password: 私有测试密码, network: ws, ws-opts: {path: /传输, headers: {X-标签: 标签值}}}`,
		`{name: 展示名称, type: vmess, server: node.example, port: 443, uuid: fictitious-native-uuid, alterId: 0, cipher: auto, network: http, http-opts: {headers: {X-标签: [标签值]}}}`,
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: ["+source+"]"), nil)
		if err != nil || len(nodes) != 1 || !nodes[0].Supported || nodes[0].Name != "展示名称" || ValidateCanonicalNode(nodes[0].Config) != nil {
			t.Fatal("Unicode literal values or header data were rejected", err)
		}
	}
}

func TestNativeLeafRejectsRealityAndJLSFallbackEntryPoints(t *testing.T) {
	for _, source := range []string{
		`{name: Test, type: vless, server: node.example, port: 443, uuid: fictitious-native-uuid, tls: true, reality-opts: {public-key: fictitious-public-key, short-id: abcdef}}`,
		`{name: Test, type: vless, server: node.example, port: 443, uuid: fictitious-native-uuid, tls: true, REALITY_OPTS: {public-key: fictitious-public-key, short-id: abcdef}}`,
		`{name: Test, type: trojan, server: node.example, port: 443, password: fictitious-secret, jls-opts: {password: fictitious-secret}}`,
		`{name: Test, type: trojan, server: node.example, port: 443, password: fictitious-secret, JLS_OPTS: {password: fictitious-secret}}`,
		`{name: Test, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: fictitious-secret, plugin: jls, plugin-opts: {host: tls.example, password: fictitious-secret}}`,
		`{name: Test, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: fictitious-secret, PLUGIN: JLS, plugin-opts: {host: tls.example, password: fictitious-secret}}`,
		`{name: Test, type: snell, server: node.example, port: 443, psk: fictitious-secret, version: 4, obfs-opts: {mode: jls, host: tls.example, password: fictitious-secret}}`,
		`{name: Test, type: snell, server: node.example, port: 443, psk: fictitious-secret, version: 4, OBFS_OPTS: {MODE: JLS, host: tls.example, password: fictitious-secret}}`,
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: ["+source+"]"), nil)
		if err != nil || len(nodes) != 1 || nodes[0].Supported || len(nodes[0].Config) != 0 || nodes[0].Reason != ErrNodeEndpoint.Error() {
			t.Fatal("authenticated transport fallback can bypass pinned endpoint", err)
		}
		if strings.Contains(nodes[0].Reason, "fictitious") || strings.Contains(nodes[0].Reason, "tls.example") {
			t.Fatal("fallback rejection exposed private configuration")
		}
	}
	// Exercise the same VLESS map returned by the native URI helper, rather
	// than only the YAML extractor.
	converter := func(context.Context, []string) ([]URIConversion, error) {
		return []URIConversion{{Config: map[string]any{"name": "Test", "type": "vless", "server": "node.example", "port": 443, "uuid": "fictitious-native-uuid", "tls": true, "reality-opts": map[string]any{"public-key": "fictitious-public-key", "short-id": "abcdef"}}}}, nil
	}
	nodes, err := ParseWithURIConverter(context.Background(), []byte("vless://fictitious-native-uuid@node.example:443"), converter)
	if err != nil || len(nodes) != 1 || nodes[0].Supported || nodes[0].Reason != ErrNodeEndpoint.Error() {
		t.Fatal("native-converted Reality leaf bypassed capability rejection", err)
	}
}

func TestNativeHysteriaRejectsFakeTCPSystemNetworking(t *testing.T) {
	for _, fixture := range []struct {
		option  string
		allowed bool
	}{
		{"protocol: faketcp", false},
		{"PROTOCOL: FAKETCP", false},
		{"obfs-protocol: faketcp", false},
		{"OBFS_PROTOCOL: fakeTcp", false},
		{"protocol: udp", true},
		{"obfs-protocol: udp", true},
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: [{name: Test, type: hysteria, server: node.example, port: 443, auth-str: fictitious-secret, up: 100 Mbps, down: 100 Mbps, "+fixture.option+"}]"), nil)
		if err != nil || len(nodes) != 1 || nodes[0].Supported != fixture.allowed {
			t.Fatal("Hysteria system-network capability was not separated from ordinary UDP", err)
		}
		if !fixture.allowed && (nodes[0].Reason != ErrNodeRouting.Error() || len(nodes[0].Config) != 0) {
			t.Fatal("FakeTCP refusal did not use safe routing category")
		}
	}
}

func TestNativeLeafRejectsCapabilityEscapesAndAliases(t *testing.T) {
	for _, extra := range []string{
		`skip-cert-verify: maybe`, `skip-cert-verify: false, Skip_Cert_Verify: false`,
		`disable-sni: true`, `Disable_Sni: 1`, `certificate: /tmp/private-fixture`, `Private_Key: /tmp/private-fixture`,
		`interface_name: en0`, `routing_mark: 42`, `Dialer_Proxy: Other`, `ip-version: ipv6`, `rules: [MATCH,DIRECT]`, `tun: {enable: true}`,
		`ip: 8.8.8.8`, `ports: 443-445`, `port_range: 443-445`, `realm-opts: {enable: true, server-url: https://extra.example}`,
		`xhttp-opts: {download_settings: {server: extra.example, port: 443}}`,
		`ech-opts: {enable: true}`, `ech-opts: {enable: true, query-server-name: extra.example}`,
		`future-native-option: {server: extra.example}`, `future-native-option: {private_key: /tmp/private-fixture}`,
		`plugin: /tmp/execute`, `sni: one.example, servername: two.example`,
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: [{name: Test, type: trojan, server: node.example, port: 443, password: fictitious-secret, "+extra+"}]"), nil)
		if err != nil || len(nodes) != 1 || nodes[0].Supported || nodes[0].Reason == "" || len(nodes[0].Config) != 0 {
			t.Fatalf("capability escape accepted for fixed fixture %d", len(extra))
		}
		if strings.Contains(nodes[0].Reason, "private-fixture") || strings.Contains(nodes[0].Reason, "extra.example") {
			t.Fatal("capability error reflected private fields")
		}
	}
}

func TestNativeLeafKeepsLegacyCanonicalIdentityAndSafeTLS(t *testing.T) {
	const source = "proxies: [{name: Existing, type: trojan, server: NODE.example, port: 443, password: fictitious-secret, servername: tls.example, skip-cert-verify: false}]"
	old, err := Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	native, err := ParseWithURIConverter(context.Background(), []byte(source), nil)
	if err != nil || !native[0].Supported || native[0].ID != old[0].ID {
		t.Fatal("existing canonical identity changed", err)
	}
	for _, extra := range []string{`skip_cert_verify: false`, `skip-cert-verify: 0`, `disable-sni: false`, `ech-opts: {enable: true, config: ZmljdGl0aW91cy1pbmxpbmUtY29uZmln}`} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: [{name: Test, type: trojan, server: node.example, port: 443, password: fictitious-secret, "+extra+"}]"), nil)
		if err != nil || !nodes[0].Supported {
			t.Fatal("redundant safe TLS option rejected", err)
		}
	}
}

func TestNativePolicyAliasesAndDefaultSNI(t *testing.T) {
	for _, extra := range []string{`sni: ""`, `servername: "", sni: tls.example`, `sni: TLS.example, servername: tls.example`} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: [{name: Test, type: trojan, server: node.example, port: 443, password: fictitious-secret, "+extra+"}]"), nil)
		if err != nil || !nodes[0].Supported {
			t.Fatal("core default or equivalent SNI rejected", err)
		}
	}
	for _, source := range []string{
		`{name: Test, type: ssh, server: node.example, port: 22, username: fixture, password: fictitious-secret, Host_Key: ["ssh-ed25519 fictitious-public-key"]}`,
		`{name: Test, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: fictitious-secret, PLUGIN: v2ray-plugin, plugin-opts: {mode: websocket, path: /transport}}`,
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: ["+source+"]"), nil)
		if err != nil || !nodes[0].Supported || ValidateCanonicalNode(nodes[0].Config) != nil {
			t.Fatal("audited native option alias lost", err)
		}
	}
	for _, source := range []string{
		`{name: Test, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: fictitious-secret, PLUGIN: /tmp/private-fixture}`,
		`{name: Test, type: vmess, server: node.example, port: 443, uuid: fixture, network: mekya}`,
	} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: ["+source+"]"), nil)
		if err != nil || nodes[0].Supported {
			t.Fatal("policy alias or endpoint transport bypassed capability check")
		}
	}
}

func TestNativeMalformedOptionValuesNeverPanicOrReachStore(t *testing.T) {
	for _, extra := range []map[string]any{
		{"sni": []any{"tls.example"}, "servername": []any{"tls.example"}},
		{"sni": map[string]any{"value": "tls.example"}, "servername": "tls.example"},
		{"future-native-option": json.Number("1e9999")},
		{"future-native-option": json.Number("NaN")},
		{"future-native-option": math.Inf(1)},
	} {
		convert := func(context.Context, []string) ([]URIConversion, error) {
			m := map[string]any{"name": "Test", "type": "trojan", "server": "node.example", "port": 443, "password": "fictitious-secret"}
			for key, value := range extra {
				m[key] = value
			}
			return []URIConversion{{Config: m}}, nil
		}
		nodes, err := ParseWithURIConverter(context.Background(), []byte("trojan://fictitious-secret@node.example:443"), convert)
		if err != nil || len(nodes) != 1 || nodes[0].Supported || len(nodes[0].Config) != 0 {
			t.Fatal("malformed native option reached storage")
		}
	}
}

func TestNativeDisplayMetadataCannotRejectOrChangeConnectionIdentity(t *testing.T) {
	var identity string
	for _, name := range []any{"Display", "unsafe\nlabel", strings.Repeat("long", 100), map[string]any{"private-key": "/tmp/unused-display"}, 42} {
		converter := func(context.Context, []string) ([]URIConversion, error) {
			return []URIConversion{{Config: map[string]any{"name": name, "type": "trojan", "server": "node.example", "port": 443, "password": "fictitious-secret"}}}, nil
		}
		nodes, err := ParseWithURIConverter(context.Background(), []byte("trojan://fictitious-secret@node.example:443"), converter)
		if err != nil || len(nodes) != 1 || !nodes[0].Supported || !validName(nodes[0].Name) {
			t.Fatal("display-only metadata rejected a valid connection", err)
		}
		if identity == "" {
			identity = nodes[0].ID
		}
		if nodes[0].ID != identity || nodes[0].Config["name"] != nil {
			t.Fatal("display metadata entered runtime identity")
		}
	}
}

func TestNativeConversionFailureDoesNotUseLegacyParser(t *testing.T) {
	const uri = "http://node.example:8080#Display"
	for _, converter := range []URIConverter{nil, func(context.Context, []string) ([]URIConversion, error) {
		return nil, errors.New("private-helper-stderr")
	}, func(context.Context, []string) ([]URIConversion, error) { return []URIConversion{}, nil }} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte(uri), converter)
		if !errors.Is(err, ErrNativeConversion) || nodes != nil {
			t.Fatal("native failure silently fell back or reflected helper error")
		}
	}
}
