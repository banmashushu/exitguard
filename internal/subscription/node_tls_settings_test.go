package subscription

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"exitguard/internal/model"
)

func TestNativeNodeHonorsDeclaredCertificateSetting(t *testing.T) {
	for _, tc := range []struct {
		option string
		skip   bool
	}{
		{"skip-cert-verify: true", true},
		{"Skip_Cert_Verify: 1", true},
		{"skip_cert_verify: \"true\"", true},
		{"skip-cert-verify: false", false},
		{"skip-cert-verify: 0", false},
		{"", false},
	} {
		t.Run(tc.option, func(t *testing.T) {
			source := "proxies: [{name: Test, type: trojan, server: node.example, port: 443, password: fictitious-private-password"
			if tc.option != "" {
				source += ", " + tc.option
			}
			source += "}]"
			lib := Empty()
			record, err := lib.PrepareWithURIConverter(context.Background(), model.SubscriptionInput{Name: "Fixture", Content: []byte(source)}, nil, nil)
			if err != nil || len(record.Nodes) != 1 || !record.Nodes[0].Supported {
				t.Fatal("declared node certificate setting was rejected", err)
			}
			node := record.Nodes[0]
			if (node.Config["skip-cert-verify"] == true) != tc.skip || node.Config["tls"] != true {
				t.Fatal("node certificate option changed or TLS encryption was removed")
			}
			if err = lib.Put(record); err != nil {
				t.Fatal(err)
			}
			wire, err := Encode(lib)
			if err != nil {
				t.Fatal("requested node setting cannot be stored", err)
			}
			restored, err := Decode(wire)
			if err != nil || restored.Records[0].Nodes[0].ID != node.ID || (restored.Records[0].Nodes[0].Config["skip-cert-verify"] == true) != tc.skip {
				t.Fatal("private roundtrip lost the requested setting or identity", err)
			}
			public, _ := json.Marshal(PublicNodes(record.Nodes))
			if strings.Contains(string(public), "fictitious-private-password") || strings.Contains(string(public), "node.example") {
				t.Fatal("public metadata leaked connection settings")
			}
			if strings.Contains(string(public), `"skipsTLSVerification":true`) != tc.skip {
				t.Fatal("public metadata does not identify the node certificate behavior")
			}
		})
	}
}

func TestNativeCertificateSettingDoesNotAffectOtherNodes(t *testing.T) {
	nodes, err := ParseWithURIConverter(context.Background(), []byte(`proxies:
  - {name: Requested, type: trojan, server: node.example, port: 443, password: fictitious-secret, skip-cert-verify: true}
  - {name: Default, type: trojan, server: node.example, port: 443, password: fictitious-secret}
`), nil)
	if err != nil || len(nodes) != 2 || !nodes[0].Supported || !nodes[1].Supported {
		t.Fatal("node-specific settings were not preserved", err)
	}
	if nodes[0].Config["skip-cert-verify"] != true || nodes[1].Config["skip-cert-verify"] != nil || nodes[0].ID == nodes[1].ID {
		t.Fatal("node setting spread to a different node or lost its identity")
	}
}

func TestTrojanURIHonorsAllowInsecure(t *testing.T) {
	for _, value := range []string{"true", "1", "TRUE"} {
		nodes, err := Parse([]byte("trojan://fictitious-password@node.example:443?allowInsecure=" + value + "&sni=tls.example"))
		if err != nil || len(nodes) != 1 || !nodes[0].Supported || nodes[0].Config["skip-cert-verify"] != true || nodes[0].Config["sni"] != "tls.example" || nodes[0].Config["tls"] != true {
			t.Fatal("Trojan's declared certificate setting was not preserved", err)
		}
	}
}

func TestNativeCertificateSettingCannotDisableProtocolTLS(t *testing.T) {
	for _, extra := range []string{`skip-cert-verify: true, tls: false`, `skip-cert-verify: maybe`, `skip-cert-verify: true, Skip_Cert_Verify: false`} {
		nodes, err := ParseWithURIConverter(context.Background(), []byte("proxies: [{name: Bad, type: trojan, server: node.example, port: 443, password: fictitious-secret, "+extra+"}]"), nil)
		if err != nil || len(nodes) != 1 || nodes[0].Supported {
			t.Fatal("invalid or conflicting TLS configuration was admitted", err)
		}
	}
}

func TestNestedNodeTLSSettingsRemainScopedAndVisible(t *testing.T) {
	source := `proxies:
  - {name: Nested, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: fictitious-secret, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, skip-cert-verify: true}}
  - {name: HeaderData, type: trojan, server: node.example, port: 443, password: fictitious-secret, network: ws, ws-opts: {headers: {skip-cert-verify: "true"}}}
  - {name: Default, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: fictitious-secret, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, skip-cert-verify: false}}
`
	nodes, err := ParseWithURIConverter(context.Background(), []byte(source), nil)
	if err != nil || len(nodes) != 3 || !nodes[0].Supported || !nodes[1].Supported || !nodes[2].Supported {
		t.Fatal("native TLS settings were rejected", err)
	}
	if nodes[0].Config["plugin-opts"].(map[string]any)["skip-cert-verify"] != true || nodes[2].Config["plugin-opts"].(map[string]any)["skip-cert-verify"] != false {
		t.Fatal("nested node certificate setting was lost")
	}
	public := PublicNodes(nodes)
	if !public[0].SkipsTLSVerification || public[1].SkipsTLSVerification || public[2].SkipsTLSVerification {
		t.Fatal("literal header data was mistaken for node TLS settings")
	}
}

func TestOldTLSRejectionRequestsRefreshWithoutInventingConfig(t *testing.T) {
	public := PublicNodes([]Node{{Name: "Old", Type: "trojan", Reason: ErrNodeTLSValidation.Error()}})
	if len(public) != 1 || public[0].Supported || public[0].SkipsTLSVerification || !strings.Contains(public[0].Reason, "更新订阅") {
		t.Fatal("old rejected snapshot was enabled without connection configuration")
	}
	if !validUnsupportedReason(ErrNodeTLSValidation.Error()) {
		t.Fatal("older rejected snapshots can no longer be read")
	}
}
