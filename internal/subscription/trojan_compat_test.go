package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	unsupportedURIParameterReason = "节点链接包含暂不支持的参数"
	conflictingTLSAliasReason     = "节点链接中的 TLS 名称设置相互冲突"
)

func TestTrojanSafeURICompatibilityPreservesCanonicalIdentity(t *testing.T) {
	baseline, err := Parse([]byte("trojan://fictitious-password@node.example:443?sni=tls.example&type=tcp#Baseline"))
	if err != nil || len(baseline) != 1 || !baseline[0].Supported {
		t.Fatal("baseline fixture rejected")
	}
	for _, query := range []string{
		"allowInsecure=false&peer=tls.example&sni=tls.example&type=tcp",
		"allowInsecure=0&peer=tls.example&type=TCP",
		"allowInsecure=FALSE&sni=tls.example&type=Tcp",
		"peer=TLS.EXAMPLE&sni=tls.example&type=tcp",
	} {
		t.Run(query, func(t *testing.T) {
			raw := "trojan://fictitious-password@node.example:443?" + query + "#Renamed"
			for _, content := range []string{raw, base64.StdEncoding.EncodeToString([]byte(raw))} {
				nodes, err := Parse([]byte(content))
				if err != nil || len(nodes) != 1 || !nodes[0].Supported {
					t.Fatal("safe Trojan options rejected")
				}
				n := nodes[0]
				if n.ID != baseline[0].ID || n.Config["sni"] != "tls.example" || n.Config["network"] != "tcp" || n.Config["tls"] != true {
					t.Fatal("safe compatibility changed TLS/transport/identity")
				}
				for _, key := range []string{"allowInsecure", "peer", "skip-cert-verify"} {
					if _, exists := n.Config[key]; exists {
						t.Fatal("URI compatibility flag reached core config")
					}
				}
				if ValidateCanonicalNode(n.Config) != nil {
					t.Fatal("compatibility output violates canonical store/runtime contract")
				}
			}
		})
	}
}
func TestTrojanURIRejectionCategoriesAreSafeAndStrict(t *testing.T) {
	for _, tc := range []struct{ query, reason string }{
		{"allowInsecure=fictitious-secret", unsupportedURIParameterReason},
		{"allowInsecure=", unsupportedURIParameterReason},
		{"allowInsecure=false&allowInsecure=false", unsupportedURIParameterReason},
		{"allowInsecure=false&%61llowInsecure=true", unsupportedURIParameterReason},
		{"peer=tls.example&sni=other.example", conflictingTLSAliasReason},
		{"peer=tls.example&peer=tls.example", unsupportedURIParameterReason},
		{"allowInsecure=false&peer=tls.example&sni=tls.example&type=tcp&private-query=fictitious-secret", unsupportedURIParameterReason},
		{"allowInsecure=false&skip-cert-verify=true", unsupportedURIParameterReason},
		{"allowInsecure=false&AllowInsecure=false", unsupportedURIParameterReason},
		{"encryption=none", unsupportedURIParameterReason},
		{"flow=", unsupportedURIParameterReason},
		{"flow=xtls-rprx-vision", unsupportedURIParameterReason},
	} {
		t.Run(tc.query, func(t *testing.T) {
			raw := "trojan://fictitious-password@node.example:443?" + tc.query + "#PrivateDisplay"
			nodes, err := Parse([]byte(raw))
			if err != nil || len(nodes) != 1 || nodes[0].Supported {
				t.Fatal("unsafe or unsupported Trojan query accepted")
			}
			if nodes[0].Reason != tc.reason {
				t.Fatalf("rejection category: got %q, want %q", nodes[0].Reason, tc.reason)
			}
			if !validUnsupportedReason(nodes[0].Reason) {
				t.Fatal("safe rejection reason cannot be persisted")
			}
			public, _ := json.Marshal(PublicNodes(nodes))
			for _, secret := range []string{"fictitious-secret", "fictitious-password", "node.example", "private-query", "PrivateDisplay"} {
				if strings.Contains(string(public), secret) {
					t.Fatal("public failure reflected private input")
				}
			}
		})
	}
}
func TestTrojanCompatibilityDoesNotExpandOtherProtocolQueryKeys(t *testing.T) {
	for _, scheme := range []string{"vless", "http", "socks5"} {
		user := "fictitious-user:fictitious-password"
		if scheme == "vless" {
			user = "12345678-1234-1234-1234-123456789abc"
		}
		nodes, err := Parse([]byte(scheme + "://" + user + "@node.example:443?allowInsecure=false&peer=tls.example"))
		if err != nil || len(nodes) != 1 || nodes[0].Supported {
			t.Fatal("Trojan compatibility leaked to another protocol")
		}
	}
}
func TestLegacyYAMLRetainsDeclaredCertificateSetting(t *testing.T) {
	nodes, err := Parse([]byte("proxies: [{name: PrivateDisplay, type: trojan, server: node.example, port: 443, password: fictitious-password, skip-cert-verify: true}]"))
	if err != nil || len(nodes) != 1 || !nodes[0].Supported || nodes[0].Config["skip-cert-verify"] != true || nodes[0].Reason != "" {
		t.Fatal("declared certificate behavior was not retained")
	}
}
