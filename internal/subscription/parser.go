// Package subscription handles private subscription data without executing it.
package subscription

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"exitguard/internal/model"
	"go.yaml.in/yaml/v3"
)

const MaxBytes = 5 << 20
const MaxNodes = 500

var ErrContent = errors.New("订阅内容无效、过大或包含不支持的结构；请导入节点列表")
var ErrNode = errors.New("此节点包含不支持的协议或配置字段")
var ErrNodeURI = errors.New("节点链接格式或选项暂不支持；请核对节点导出格式")
var ErrNodeProtocol = errors.New("此节点协议暂不支持")
var ErrNodeURIQuery = errors.New("节点链接包含暂不支持的参数")

// Kept for reading rejected snapshots written by earlier releases.
var ErrNodeTLSValidation = errors.New("节点要求跳过证书验证，当前不支持")
var ErrNodeTLSAlias = errors.New("节点链接中的 TLS 名称设置相互冲突")

type Node struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Supported bool           `json:"supported"`
	Reason    string         `json:"reason"`
	Config    map[string]any `json:"config"`
}

func PublicNodes(nodes []Node) []model.SubscriptionNode {
	out := make([]model.SubscriptionNode, 0, len(nodes))
	for _, n := range nodes {
		reason := n.Reason
		if !n.Supported && reason == ErrNodeTLSValidation.Error() {
			reason = "旧导入结果；请更新订阅或重新导入，以应用节点证书设置"
		}
		out = append(out, model.SubscriptionNode{ID: n.ID, Name: n.Name, Type: n.Type, Supported: n.Supported, Reason: reason, SkipsTLSVerification: n.Supported && nodeSkipsTLSVerification(n.Config, 0)})
	}
	return out
}
func validName(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && len(s) <= 120 && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func Parse(content []byte) ([]Node, error) {
	return parse(context.Background(), content, nil, false)
}

func ParseWithURIConverter(ctx context.Context, content []byte, converter URIConverter) ([]Node, error) {
	return parse(ctx, content, converter, true)
}

func parse(ctx context.Context, content []byte, converter URIConverter, native bool) ([]Node, error) {
	if ctx.Err() != nil {
		return nil, ErrNativeConversion
	}
	if len(content) > MaxBytes || !utf8.Valid(content) {
		return nil, ErrContent
	}
	if failure := sourceResponseFailure(content); failure != nil {
		return nil, failure
	}
	raw := strings.TrimSpace(strings.TrimPrefix(string(content), "\ufeff"))
	if raw == "" {
		return nil, ErrContent
	}
	// URI/Base64 content is disjoint from YAML. Decode at most once.
	if !strings.Contains(raw, "://") && !strings.ContainsAny(raw, ":{}[]") {
		if decoded, err := decode64(raw); err == nil && len(decoded) <= MaxBytes && bytes.Contains(decoded, []byte("://")) {
			raw = strings.TrimSpace(string(decoded))
		}
	}
	var maps []map[string]any
	uriReasons := map[int]string{}
	first := strings.SplitN(raw, "\n", 2)[0]
	if _, recognized := recognizedURIScheme(first); recognized {
		lines := strings.Split(raw, "\n")
		if len(lines) > MaxNodes {
			return nil, ErrContent
		}
		if native {
			var input []string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if _, ok := recognizedURIScheme(line); !ok {
					return nil, ErrContent
				}
				input = append(input, line)
			}
			if converter == nil {
				return nil, ErrNativeConversion
			}
			results, err := converter(ctx, input)
			if err != nil || ctx.Err() != nil || len(results) != len(input) {
				return nil, ErrNativeConversion
			}
			for i, result := range results {
				if result.Error == "invalid_uri" && len(result.Config) == 0 {
					scheme, _ := recognizedURIScheme(input[i])
					maps = append(maps, map[string]any{"name": fmt.Sprintf("无法导入的节点 %d", i+1), "type": uriMetadataType(scheme)})
					uriReasons[i] = ErrNodeURI.Error()
				} else if result.Error != "" || len(result.Config) == 0 {
					return nil, ErrNativeConversion
				} else {
					maps = append(maps, result.Config)
				}
			}
		} else {
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				scheme, recognized := recognizedURIScheme(line)
				if !recognized {
					return nil, ErrContent
				}
				m, err := uriNode(line)
				if err != nil {
					m = map[string]any{"name": fmt.Sprintf("不支持的节点 %d", len(maps)+1), "type": uriMetadataType(scheme)}
					reason := ErrNodeURI.Error()
					switch err {
					case ErrNodeURIQuery, ErrNodeTLSValidation, ErrNodeTLSAlias:
						reason = err.Error()
					}
					switch scheme {
					case "http", "https", "socks5", "ss", "vmess", "vless", "trojan":
					default:
						reason = ErrNodeProtocol.Error()
					}
					uriReasons[len(maps)] = reason
				}
				maps = append(maps, m)
			}
		}
	} else {
		var root yaml.Node
		d := yaml.NewDecoder(strings.NewReader(raw))
		if d.Decode(&root) != nil || checkYAML(&root, 0) != nil {
			return nil, ErrContent
		}
		var extra yaml.Node
		if d.Decode(&extra) != io.EOF {
			return nil, ErrContent
		}
		if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
			return nil, ErrContent
		}
		mapping := root.Content[0]
		var proxies *yaml.Node
		for i := 0; i < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == "proxies" {
				proxies = mapping.Content[i+1]
			}
		}
		if proxies == nil || proxies.Kind != yaml.SequenceNode || len(proxies.Content) == 0 || len(proxies.Content) > MaxNodes {
			return nil, ErrContent
		}
		for _, item := range proxies.Content {
			var m map[string]any
			if item.Decode(&m) != nil || m == nil {
				return nil, ErrContent
			}
			maps = append(maps, m)
		}
	}
	if len(maps) == 0 || len(maps) > MaxNodes {
		return nil, ErrContent
	}
	out := make([]Node, 0, len(maps))
	seen := map[string]bool{}
	for index, m := range maps {
		name, _ := m["name"].(string)
		typ, _ := m["type"].(string)
		if !validName(name) {
			name = fmt.Sprintf("节点 %d", len(out)+1)
		}
		n := Node{Name: name, Type: safeType(typ), Reason: ErrNode.Error()}
		if reason, exists := uriReasons[index]; exists {
			n.Reason = reason
		}
		var config map[string]any
		var err error
		if native {
			config, err = nativeLeaf(m)
		} else {
			config, err = canonicalNode(m)
		}
		if err == nil {
			n.Config = config
			n.Type = safeType(config["type"].(string))
			n.Supported = true
			n.Reason = ""
			n.ID = Identity(config)
		} else {
			if _, uriFailure := uriReasons[index]; !uriFailure {
				switch err {
				case ErrNodeURIQuery, ErrNodeTLSValidation, ErrNodeTLSConfig, ErrNodeSSHHostKey, ErrNodeTLSAlias, ErrNodeFile, ErrNodeEndpoint, ErrNodeRouting, ErrNodeCapability:
					n.Reason = err.Error()
				}
			}
			sum := sha256.Sum256([]byte(fmt.Sprintf("unsupported:%d:%s:%s", len(out), name, n.Type)))
			n.ID = hex.EncodeToString(sum[:])
		}
		if seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		out = append(out, n)
	}
	return out, nil
}
func checkYAML(n *yaml.Node, depth int) error {
	if depth > 24 || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return ErrContent
	}
	switch n.Tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!bool", "!!float", "!!null", "!!timestamp":
	default:
		return ErrContent
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] || k.Value == "<<" {
				return ErrContent
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if checkYAML(child, depth+1) != nil {
			return ErrContent
		}
	}
	return nil
}
func safeType(s string) string {
	switch strings.ToLower(s) {
	case "http", "socks5", "ss", "vmess", "vless", "trojan", "ssr", "hysteria", "hysteria2", "tuic", "wireguard", "anytls", "ssh", "snell", "mieru":
		return strings.ToLower(s)
	}
	return "unsupported"
}

// Only explicitly known node URI families can start or continue a URI list.
// An arbitrary error page containing :// must not become a saved node snapshot.
func recognizedURIScheme(line string) (string, bool) {
	at := strings.Index(line, "://")
	if at < 1 || at > 20 {
		return "", false
	}
	scheme := strings.ToLower(line[:at])
	switch scheme {
	case "http", "https", "socks5", "socks5h", "socks", "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "hysteria2+realm", "hy2+realm", "tuic", "wireguard", "wg", "anytls", "ssh", "snell", "mieru", "mierus":
		return scheme, true
	}
	return "", false
}
func uriMetadataType(scheme string) string {
	switch scheme {
	case "https":
		return "http"
	case "socks", "socks5h":
		return "socks5"
	case "hy2", "hysteria2+realm", "hy2+realm":
		return "hysteria2"
	case "mierus":
		return "mieru"
	case "wg":
		return "wireguard"
	}
	return safeType(scheme)
}
func validUnsupportedReason(reason string) bool {
	switch reason {
	case ErrNode.Error(), ErrNodeURI.Error(), ErrNodeProtocol.Error(), ErrNodeURIQuery.Error(), ErrNodeTLSValidation.Error(), ErrNodeTLSConfig.Error(), ErrNodeSSHHostKey.Error(), ErrNodeTLSAlias.Error(), ErrNodeFile.Error(), ErrNodeEndpoint.Error(), ErrNodeRouting.Error(), ErrNodeCapability.Error():
		return true
	}
	return false
}
func Identity(config map[string]any) string {
	b, _ := json.Marshal(config)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func ValidateCanonicalNode(config map[string]any) error {
	m := map[string]any{"name": "Validated"}
	for k, v := range config {
		m[k] = v
	}
	c, err := nativeLeaf(m)
	if err != nil {
		return ErrNode
	}
	a, _ := json.Marshal(c)
	b, _ := json.Marshal(config)
	if !bytes.Equal(a, b) {
		return ErrNode
	}
	return nil
}
func canonicalNode(m map[string]any) (map[string]any, error) {
	typ, _ := m["type"].(string)
	typ = strings.ToLower(typ)
	allowed := map[string]bool{}
	for _, k := range []string{"name", "type", "server", "port", "udp", "tls", "servername", "sni", "alpn", "client-fingerprint", "skip-cert-verify"} {
		allowed[k] = true
	}
	switch typ {
	case "http", "socks5":
		allowed["username"], allowed["password"] = true, true
	case "ss":
		allowed["cipher"], allowed["password"] = true, true
	case "vmess":
		allowed["uuid"], allowed["alterId"], allowed["cipher"] = true, true, true
		fallthrough
	case "vless":
		allowed["uuid"], allowed["flow"], allowed["network"], allowed["ws-opts"], allowed["grpc-opts"] = true, true, true, true, true
	case "trojan":
		allowed["password"], allowed["network"], allowed["ws-opts"], allowed["grpc-opts"] = true, true, true, true
	default:
		return nil, ErrNode
	}
	if value, exists := m["skip-cert-verify"]; exists {
		_, ok := value.(bool)
		if !ok {
			return nil, ErrNode
		}
	}
	for key := range m {
		if !allowed[key] {
			return nil, ErrNode
		}
	}
	server, ok := m["server"].(string)
	server = strings.ToLower(strings.TrimSpace(server))
	if !ok || !validServer(server) {
		return nil, ErrNode
	}
	port, ok := integer(m["port"])
	if !ok || port < 1 || port > 65535 {
		return nil, ErrNode
	}
	c := map[string]any{"type": typ, "server": server, "port": port, "udp": false}
	if m["skip-cert-verify"] == true {
		c["skip-cert-verify"] = true
	}
	if v, exists := m["udp"]; exists {
		if _, ok := v.(bool); !ok {
			return nil, ErrNode
		}
	}
	str := func(key string, required bool) error {
		v, exists := m[key]
		if !exists {
			if required {
				return ErrNode
			}
			return nil
		}
		s, ok := v.(string)
		if !ok || len(s) > 4096 || strings.IndexFunc(s, unicode.IsControl) >= 0 || required && s == "" {
			return ErrNode
		}
		if s != "" {
			c[key] = s
		}
		return nil
	}
	switch typ {
	case "http", "socks5":
		if str("username", false) != nil || str("password", false) != nil {
			return nil, ErrNode
		}
		if (c["username"] == nil) != (c["password"] == nil) {
			return nil, ErrNode
		}
	case "ss":
		if str("cipher", true) != nil || str("password", true) != nil {
			return nil, ErrNode
		}
		switch c["cipher"] {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		default:
			return nil, ErrNode
		}
	case "vmess", "vless":
		if str("uuid", true) != nil || !validUUID(c["uuid"].(string)) {
			return nil, ErrNode
		}
		c["uuid"] = strings.ToLower(c["uuid"].(string))
		if typ == "vmess" {
			if v, exists := m["alterId"]; exists {
				n, ok := integer(v)
				if !ok || n != 0 {
					return nil, ErrNode
				}
			}
			c["alterId"] = 0
			if str("cipher", false) != nil {
				return nil, ErrNode
			}
			if c["cipher"] == nil {
				c["cipher"] = "auto"
			}
			switch c["cipher"] {
			case "auto", "aes-128-gcm", "chacha20-poly1305":
			default:
				return nil, ErrNode
			}
		}
	case "trojan":
		if str("password", true) != nil {
			return nil, ErrNode
		}
	}
	tlsEnabled := typ == "trojan"
	if value, exists := m["tls"]; exists {
		b, ok := value.(bool)
		if !ok || typ == "trojan" && !b {
			return nil, ErrNode
		}
		tlsEnabled = b
	}
	if tlsEnabled {
		c["tls"] = true
	}
	if str("servername", false) != nil || str("sni", false) != nil {
		return nil, ErrNode
	}
	if name, ok := c["sni"].(string); ok {
		if other, exists := c["servername"]; exists && other != name {
			return nil, ErrNode
		}
		c["servername"] = name
		delete(c, "sni")
	}
	if name, exists := c["servername"]; exists {
		if !tlsEnabled || !validServer(name.(string)) {
			return nil, ErrNode
		}
	}
	if value, exists := m["alpn"]; exists {
		if !tlsEnabled {
			return nil, ErrNode
		}
		list, ok := stringList(value)
		if !ok || len(list) > 4 {
			return nil, ErrNode
		}
		for _, item := range list {
			if item != "h2" && item != "http/1.1" && item != "h3" {
				return nil, ErrNode
			}
		}
		c["alpn"] = list
	}
	if str("client-fingerprint", false) != nil {
		return nil, ErrNode
	}
	if fp, exists := c["client-fingerprint"]; exists {
		if !tlsEnabled {
			return nil, ErrNode
		}
		switch fp {
		case "chrome", "firefox", "safari", "ios", "edge":
		default:
			return nil, ErrNode
		}
	}
	if str("flow", false) != nil {
		return nil, ErrNode
	}
	if flow, exists := c["flow"]; exists {
		if typ != "vless" || flow != "xtls-rprx-vision" || !tlsEnabled {
			return nil, ErrNode
		}
	}
	network := "tcp"
	if value, exists := m["network"]; exists {
		var ok bool
		network, ok = value.(string)
		if !ok {
			return nil, ErrNode
		}
	}
	if network != "tcp" && network != "ws" && network != "grpc" {
		return nil, ErrNode
	}
	if typ == "vmess" || typ == "vless" || typ == "trojan" {
		c["network"] = network
	}
	if _, exists := m["ws-opts"]; exists {
		if network != "ws" {
			return nil, ErrNode
		}
		opts, ok := m["ws-opts"].(map[string]any)
		if !ok {
			return nil, ErrNode
		}
		clean := map[string]any{}
		for key, value := range opts {
			switch key {
			case "path":
				v, ok := value.(string)
				if !ok || len(v) > 2048 || !strings.HasPrefix(v, "/") || strings.IndexFunc(v, unicode.IsControl) >= 0 {
					return nil, ErrNode
				}
				clean[key] = v
			case "headers":
				headers, ok := value.(map[string]any)
				if !ok || len(headers) != 1 {
					return nil, ErrNode
				}
				host, ok := headers["Host"].(string)
				if !ok || !validServer(host) {
					return nil, ErrNode
				}
				clean[key] = map[string]any{"Host": host}
			default:
				return nil, ErrNode
			}
		}
		c["ws-opts"] = clean
	}
	if _, exists := m["grpc-opts"]; exists {
		if network != "grpc" {
			return nil, ErrNode
		}
		opts, ok := m["grpc-opts"].(map[string]any)
		if !ok || len(opts) != 1 {
			return nil, ErrNode
		}
		v, ok := opts["grpc-service-name"].(string)
		if !ok || len(v) > 255 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return nil, ErrNode
		}
		c["grpc-opts"] = map[string]any{"grpc-service-name": v}
	}
	if typ == "ss" {
		for _, key := range []string{"tls", "servername", "sni", "alpn", "client-fingerprint"} {
			if _, exists := m[key]; exists {
				return nil, ErrNode
			}
		}
	}
	if typ == "http" || typ == "socks5" {
		for _, key := range []string{"alpn", "client-fingerprint"} {
			if _, exists := m[key]; exists {
				return nil, ErrNode
			}
		}
	}
	if typ == "http" || typ == "socks5" || typ == "trojan" {
		if value, exists := c["servername"]; exists {
			c["sni"] = value
			delete(c, "servername")
		}
	}
	return c, nil
}
func integer(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), int64(int(n)) == n
	case float64:
		return int(n), n == float64(int(n))
	case json.Number:
		i, e := strconv.Atoi(string(n))
		return i, e == nil
	case string:
		i, e := strconv.Atoi(n)
		return i, e == nil
	}
	return 0, false
}
func stringList(v any) ([]string, bool) {
	if list, ok := v.([]string); ok {
		return list, true
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil
}
func validServer(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, ":/@?#\\%[]") || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return false
	}
	if ip, e := netip.ParseAddr(s); e == nil {
		return PublicIPv4(ip)
	}
	if strings.EqualFold(s, "localhost") || strings.HasSuffix(s, ".localhost") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func decode64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := encoding.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, ErrContent
}
func uriNode(raw string) (map[string]any, error) {
	u, e := url.Parse(raw)
	if e != nil || u == nil {
		return nil, ErrNode
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "vmess" {
		b, e := decode64(strings.TrimPrefix(raw, "vmess://"))
		if e != nil || len(b) > 65536 {
			return nil, ErrNode
		}
		var v map[string]any
		if strictJSON(b) != nil || json.Unmarshal(b, &v) != nil {
			return nil, ErrNode
		}
		m := map[string]any{"type": "vmess", "name": v["ps"], "server": v["add"], "port": v["port"], "uuid": v["id"], "cipher": "auto"}
		for key := range v {
			switch key {
			case "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp":
			default:
				return nil, ErrNode
			}
		}
		if aid, exists := v["aid"]; exists {
			m["alterId"] = aid
		}
		if x, exists := v["type"]; exists && x != "" && x != "none" {
			return nil, ErrNode
		}
		if x, exists := v["tls"]; exists && x != "" && x != "none" && x != "tls" {
			return nil, ErrNode
		}
		if x, exists := v["scy"]; exists && x != "" {
			m["cipher"] = x
		}
		if x, exists := v["fp"]; exists && x != "" {
			m["client-fingerprint"] = x
		}
		if x, exists := v["alpn"]; exists && x != "" {
			str, ok := x.(string)
			if !ok {
				return nil, ErrNode
			}
			m["alpn"] = strings.Split(str, ",")
		}
		network, _ := v["net"].(string)
		if network == "" {
			network = "tcp"
		}
		if network != "ws" && v["host"] != nil && v["host"] != "" {
			return nil, ErrNode
		}
		if network != "ws" && network != "grpc" && v["path"] != nil && v["path"] != "" {
			return nil, ErrNode
		}
		m["network"] = network
		if v["tls"] == "tls" {
			m["tls"] = true
		}
		if s, ok := v["sni"].(string); ok && s != "" {
			m["servername"] = s
		}
		if network == "ws" {
			opts := map[string]any{}
			if p, ok := v["path"].(string); ok && p != "" {
				opts["path"] = p
			}
			if h, ok := v["host"].(string); ok && h != "" {
				opts["headers"] = map[string]any{"Host": h}
			}
			m["ws-opts"] = opts
		}
		if network == "grpc" {
			m["grpc-opts"] = map[string]any{"grpc-service-name": v["path"]}
		}
		return m, nil
	}
	if scheme == "ss" && u.User == nil {
		b, e := decode64(strings.TrimSuffix(strings.TrimPrefix(raw, "ss://"), "#"+u.Fragment))
		if e != nil {
			return nil, ErrNode
		}
		fragment := u.Fragment
		u, e = url.Parse("ss://" + string(b))
		if e == nil {
			u.Fragment = fragment
		}
		if e != nil {
			return nil, ErrNode
		}
	}
	if u.User == nil && scheme != "http" && scheme != "https" && scheme != "socks5" || u.Hostname() == "" || u.Port() == "" || u.Path != "" && u.Path != "/" {
		return nil, ErrNode
	}
	name := u.Fragment
	if name == "" {
		name = "导入节点"
	}
	m := map[string]any{"name": name, "type": scheme, "server": u.Hostname(), "port": u.Port()}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return nil, ErrNodeURIQuery
	}
	for key, values := range q {
		if len(values) != 1 {
			return nil, ErrNodeURIQuery
		}
		switch key {
		case "type", "security", "sni", "host", "path", "serviceName", "fp", "alpn":
		case "flow", "encryption":
			if scheme != "vless" {
				return nil, ErrNodeURIQuery
			}
		case "allowInsecure", "peer":
			if scheme != "trojan" {
				return nil, ErrNodeURIQuery
			}
		default:
			return nil, ErrNodeURIQuery
		}
	}
	if scheme == "trojan" {
		// Mihomo v1.19.33's official URI converter maps allowInsecure to
		// skip-cert-verify. Preserve an explicit value; malformed flags never
		// inherit strconv.ParseBool's false zero value.
		if values, exists := q["allowInsecure"]; exists {
			insecure, err := strconv.ParseBool(values[0])
			if err != nil {
				return nil, ErrNodeURIQuery
			}
			if insecure {
				m["skip-cert-verify"] = true
			}
		}
		// peer is a compatibility alias, not an additional TLS setting. Never
		// override a contradictory explicit SNI or weaken certificate checks.
		if peer := q.Get("peer"); peer != "" {
			if sni := q.Get("sni"); sni != "" && !strings.EqualFold(peer, sni) {
				return nil, ErrNodeTLSAlias
			}
			if q.Get("sni") == "" {
				q.Set("sni", peer)
			}
		}
	}
	switch scheme {
	case "ss":
		if len(q) != 0 {
			return nil, ErrNodeURIQuery
		}
		if password, has := u.User.Password(); has {
			m["cipher"], m["password"] = u.User.Username(), password
		} else {
			b, e := decode64(u.User.Username())
			if e != nil {
				return nil, ErrNode
			}
			pair := strings.SplitN(string(b), ":", 2)
			if len(pair) != 2 {
				return nil, ErrNode
			}
			m["cipher"], m["password"] = pair[0], pair[1]
		}

	case "http", "https", "socks5":
		if len(q) != 0 {
			return nil, ErrNodeURIQuery
		}
		if scheme == "https" {
			m["type"] = "http"
			m["tls"] = true
		}
		if u.User != nil {
			m["username"] = u.User.Username()
			p, _ := u.User.Password()
			m["password"] = p
		}
	case "vless":
		m["uuid"] = u.User.Username()
		if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
			return nil, ErrNode
		}
	case "trojan":
		m["password"] = u.User.Username()
		m["tls"] = true
	default:
		return nil, ErrNode
	}
	if scheme == "vless" || scheme == "trojan" {
		network := q.Get("type")
		if scheme == "trojan" {
			network = strings.ToLower(network)
		}
		if network == "" {
			network = "tcp"
		}
		if network != "ws" && (q.Get("path") != "" || q.Get("host") != "") {
			return nil, ErrNode
		}
		if network != "grpc" && q.Get("serviceName") != "" {
			return nil, ErrNode
		}
		m["network"] = network
		security := q.Get("security")
		if scheme == "trojan" && security == "none" {
			return nil, ErrNode
		}
		if security != "" && security != "none" && security != "tls" {
			return nil, ErrNode
		}
		if security == "tls" {
			m["tls"] = true
		}
		if flow := q.Get("flow"); flow != "" {
			m["flow"] = flow
		}
		if network == "ws" {
			opts := map[string]any{}
			if p := q.Get("path"); p != "" {
				opts["path"] = p
			}
			if h := q.Get("host"); h != "" {
				opts["headers"] = map[string]any{"Host": h}
			}
			m["ws-opts"] = opts
		}
		if network == "grpc" {
			m["grpc-opts"] = map[string]any{"grpc-service-name": q.Get("serviceName")}
		}
	}
	if s := q.Get("sni"); s != "" {
		m["servername"] = s
	}
	if fp := q.Get("fp"); fp != "" {
		m["client-fingerprint"] = fp
	}
	if alpn := q.Get("alpn"); alpn != "" {
		m["alpn"] = strings.Split(alpn, ",")
	}
	return m, nil
}
