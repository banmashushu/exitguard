package subscription

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// URIConverter calls the separately packaged core converter without constructing
// proxy adapters. Results correspond exactly to input lines and never carry raw
// parser errors across the private process boundary.
type URIConverter func(context.Context, []string) ([]URIConversion, error)

type URIConversion struct {
	Config map[string]any `json:"config,omitempty"`
	Error  string         `json:"error,omitempty"`
}

var ErrNativeConversion = errors.New("内核节点转换失败；请检查应用完整性或重新安装后再导入")
var ErrNodeFile = errors.New("此节点依赖本机文件，当前不能选择")
var ErrNodeEndpoint = errors.New("此节点需要额外端点或动态地址，当前不能选择")
var ErrNodeRouting = errors.New("此节点包含外部控制、网卡或路由设置，当前不能选择")
var ErrNodeCapability = errors.New("此节点超出当前单服务器代理能力，暂不能选择")
var ErrNodeTLSConfig = errors.New("节点的 TLS 参数无效或互相冲突")
var ErrNodeSSHHostKey = errors.New("SSH 节点需要明确的服务器公钥校验配置")

// The pinned core treats case and underscore/hyphen aliases as the same option.
// Audit before any legacy normalization, including nested protocol options.
func nativeKey(key string) string { return strings.ToLower(strings.ReplaceAll(key, "_", "-")) }

func nativeLeaf(m map[string]any) (map[string]any, error) {
	budget := 4096
	value, err := boundedNativeValue(m, 0, false, &budget)
	if err != nil {
		return nil, err
	}
	c := value.(map[string]any)
	// Primary identity fields use one spelling. Other native option spellings
	// remain intact so transport headers and protocol authentication stay exact.
	for key, value := range c {
		switch canonical := nativeKey(key); canonical {
		case "name", "type", "server", "port", "udp", "tls", "sni", "servername", "network", "uuid", "plugin", "host-key":
			delete(c, key)
			c[canonical] = value
		case "alterid":
			delete(c, key)
			c["alterId"] = value
		}
	}
	delete(c, "name")
	typ, _ := c["type"].(string)
	typ = strings.ToLower(typ)
	switch typ {
	case "http", "socks5", "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "snell", "mieru", "ssh":
	default:
		return nil, ErrNodeCapability
	}
	server, ok := c["server"].(string)
	server = strings.ToLower(strings.TrimSpace(server))
	if !ok || !validServer(server) {
		return nil, ErrNodeEndpoint
	}
	port, ok := integer(c["port"])
	if !ok || port < 1 || port > 65535 {
		return nil, ErrNodeEndpoint
	}
	c["type"], c["server"], c["port"] = typ, server, port
	if typ == "hysteria" {
		for key, value := range c {
			if option := nativeKey(key); option == "protocol" || option == "obfs-protocol" {
				// Pinned Hysteria FakeTCP can modify system packet-filter rules
				// on Linux, unlike the ordinary owned UDP transport.
				if protocol, ok := value.(string); ok && strings.EqualFold(protocol, "faketcp") {
					return nil, ErrNodeRouting
				}
			}
		}
	}
	if value, exists := c["udp"]; exists {
		if _, ok := value.(bool); !ok {
			return nil, ErrNode
		}
	} else {
		c["udp"] = false
	}
	if value, exists := c["tls"]; exists {
		b, ok := value.(bool)
		if !ok || typ == "trojan" && !b {
			return nil, ErrNodeTLSConfig
		}
	} else if typ == "trojan" {
		c["tls"] = true
	}
	if typ == "vmess" || typ == "vless" || typ == "trojan" {
		if _, exists := c["network"]; !exists {
			c["network"] = "tcp"
		}
	}
	if network, ok := c["network"].(string); ok && strings.EqualFold(network, "mekya") {
		return nil, ErrNodeEndpoint
	}
	if typ == "ssh" {
		keys, ok := stringList(c["host-key"])
		if !ok || len(keys) == 0 {
			return nil, ErrNodeSSHHostKey
		}
	}
	var tlsName string
	for _, key := range []string{"sni", "servername"} {
		if value, exists := c[key]; exists {
			text, ok := value.(string)
			if !ok || text != "" && !validServer(text) {
				return nil, ErrNodeTLSAlias
			}
			if text != "" {
				if tlsName != "" && !strings.EqualFold(tlsName, text) {
					return nil, ErrNodeTLSAlias
				}
				tlsName = text
			}
			delete(c, key)
		}
	}
	if tlsName != "" {
		if typ == "vmess" || typ == "vless" {
			c["servername"] = tlsName
		} else {
			c["sni"] = tlsName
		}
	}
	if plugin, exists := c["plugin"]; exists {
		if typ != "ss" {
			return nil, ErrNodeCapability
		}
		name, ok := plugin.(string)
		if !ok {
			return nil, ErrNodeCapability
		}
		// The pinned JLS transport's authentication-failure HTTP fallback can
		// follow a redirect using an unconstrained default dialer.
		if strings.EqualFold(name, "jls") {
			return nil, ErrNodeEndpoint
		}
		// These names select built-in Go transports, never external executables.
		switch name {
		case "", "obfs", "v2ray-plugin", "gost-plugin", "shadow-tls", "restls", "kcptun":
		default:
			return nil, ErrNodeFile
		}
	}
	if raw, err := json.Marshal(c); err != nil || len(raw) > 64*1024 {
		return nil, ErrNode
	}
	// Preserve established canonical defaults/identities where no native option
	// would be lost. The old canonicalizer deliberately forced UDP off; native
	// explicit true is retained, while the owned listener remains TCP-only.
	if c["udp"] != true {
		if legacy, err := canonicalNode(c); err == nil {
			return legacy, nil
		}
	}
	return c, nil
}

func safeFalse(value any) bool {
	switch value := value.(type) {
	case bool:
		return !value
	case int:
		return value == 0
	case int64:
		return value == 0
	case float64:
		return value == 0
	case json.Number:
		return value == "0"
	case string:
		return value == "false" || value == "0"
	}
	return false
}

// Clone only bounded JSON-compatible values. Unlike a per-protocol schema this
// preserves future native options, but denies capabilities that can escape the
// single pinned server. Header maps are data, not core option namespaces.
func boundedNativeValue(value any, depth int, headers bool, budget *int) (any, error) {
	*budget--
	if depth > 16 || *budget < 0 {
		return nil, ErrNode
	}
	switch value := value.(type) {
	case map[string]any:
		if len(value) > 256 {
			return nil, ErrNode
		}
		out := make(map[string]any, len(value))
		seen := map[string]bool{}
		for key, v := range value {
			alias := nativeKey(key)
			if key == "" || len(key) > 128 || !utf8.ValidString(key) || strings.IndexFunc(key, unicode.IsControl) >= 0 || seen[alias] {
				return nil, ErrNode
			}
			seen[alias] = true
			if !headers {
				// Core option matching uses Unicode EqualFold (including long-s
				// and Kelvin-sign aliases). All audited option tags are ASCII;
				// limiting this namespace avoids a weaker lowercase comparison.
				for i := range key {
					if key[i] >= utf8.RuneSelf {
						return nil, ErrNodeCapability
					}
				}
			} else {
				// An exception is only literal header data. Do not turn an
				// arbitrary nested map called headers into an audit escape.
				if _, ok := v.(string); !ok {
					if _, ok := stringList(v); !ok {
						return nil, ErrNode
					}
				}
			}
			// Display metadata never reaches the core's fixed leaf name. Keep
			// duplicate-key checks, but let Parse replace an invalid label safely.
			if depth == 0 && alias == "name" {
				continue
			}
			if !headers {
				switch alias {
				case "certificate", "private-key", "certificate-path", "private-key-path", "cert-file", "key-file", "ca-file", "ca-path", "file", "plugin-path":
					return nil, ErrNodeFile
				case "interface-name", "routing-mark", "ip-version", "dialer-proxy", "proxies", "proxy-groups", "proxy-providers", "rule-providers", "providers", "rules", "tun", "script", "listeners", "listen", "external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-ui", "external-ui-url", "external-ui-name", "secret", "dns", "hosts", "allow-lan", "bind-address":
					return nil, ErrNodeRouting
				case "ip", "ports", "port-range", "realm-opts", "stun-servers", "server-url", "download-settings", "peers", "refresh-server-ip", "tlsmirror-opts", "mekya-opts", "reality-opts", "jls-opts":
					return nil, ErrNodeEndpoint
				case "server", "port":
					if depth != 0 {
						return nil, ErrNodeEndpoint
					}
				case "path":
					if depth == 0 {
						return nil, ErrNodeFile
					}
				case "url", "query-server-name":
					return nil, ErrNodeEndpoint
				case nodeSkipCertVerify:
					flag, ok := nodeTLSBool(v)
					if !ok {
						return nil, ErrNodeTLSConfig
					}
					if flag || depth != 0 {
						out[alias] = flag
					}
					continue
				case "disable-sni", "insecure", "allow-insecure", "allowinsecure":
					// URI flags are mapped by Mihomo's converter. Avoid treating
					// other native options as aliases for certificate checking.
					if !safeFalse(v) {
						return nil, ErrNodeTLSConfig
					}
					continue
				}
				if alias == "obfs-opts" {
					if opts, ok := v.(map[string]any); ok {
						for key, value := range opts {
							if nativeKey(key) == "mode" {
								if mode, ok := value.(string); ok && strings.EqualFold(mode, "jls") {
									return nil, ErrNodeEndpoint
								}
							}
						}
					}
				}
				if alias == "ech-opts" {
					opts, ok := v.(map[string]any)
					if !ok {
						return nil, ErrNodeEndpoint
					}
					var enabled, config any
					for k, v := range opts {
						switch nativeKey(k) {
						case "enable":
							enabled = v
						case "config":
							config = v
						}
					}
					if enabled != nil && !safeFalse(enabled) {
						text, ok := config.(string)
						decoded, err := base64.StdEncoding.DecodeString(text)
						if !ok || err != nil || len(decoded) == 0 {
							return nil, ErrNodeEndpoint
						}
					}
				}
			}
			if !headers && (alias == "headers" || alias == "ws-headers") {
				if _, ok := v.(map[string]any); !ok {
					return nil, ErrNode
				}
			}
			child, err := boundedNativeValue(v, depth+1, headers || alias == "headers" || alias == "ws-headers", budget)
			if err != nil {
				return nil, err
			}
			out[key] = child
		}
		return out, nil
	case []any:
		if len(value) > 256 {
			return nil, ErrNode
		}
		out := make([]any, len(value))
		for i, v := range value {
			var err error
			out[i], err = boundedNativeValue(v, depth+1, headers, budget)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case []string:
		out := make([]any, len(value))
		for i, v := range value {
			out[i] = v
		}
		return boundedNativeValue(out, depth, headers, budget)
	case string:
		if len(value) > 16*1024 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, ErrNode
		}
		return value, nil
	case bool, int, int64, uint64:
		return value, nil
	case float64:
		if math.IsInf(value, 0) || math.IsNaN(value) {
			return nil, ErrNode
		}
		return value, nil
	case json.Number:
		if number, err := value.Float64(); err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
			return nil, ErrNode
		}
		return value, nil
	default:
		return nil, ErrNode
	}
}
