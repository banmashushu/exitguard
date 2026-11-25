package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestParserExtractsOnlySafeNodesAndStableIdentity(t *testing.T) {
	source := []byte("tun: {enable: true}\nexternal-controller: 0.0.0.0:9999\nrules: [MATCH,DIRECT]\nproxies:\n  - {name: Safe, type: ss, server: NODE.example, port: 443, cipher: aes-128-gcm, password: private-secret}\n  - {name: Bad, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: private-secret, plugin: /tmp/execute}\n")
	nodes, err := Parse(source)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("parse failed: %v", err)
	}
	if !nodes[0].Supported || nodes[1].Supported || nodes[1].Reason == "" {
		t.Fatal("unsupported node not explicitly separated")
	}
	if _, exists := nodes[0].Config["name"]; exists {
		t.Fatal("untrusted name entered core config")
	}
	other, err := Parse([]byte(strings.Replace(string(source), "name: Safe", "name: Renamed", 1)))
	if err != nil || other[0].ID != nodes[0].ID {
		t.Fatal("display rename changed connection identity")
	}
	public, _ := json.Marshal(PublicNodes(nodes))
	if strings.Contains(string(public), "private-secret") || strings.Contains(string(public), "NODE.example") || strings.Contains(string(public), "/tmp/execute") {
		t.Fatal("node public summary leaked connection data")
	}
	if err = ValidateCanonicalNode(nodes[0].Config); err != nil {
		t.Fatal(err)
	}
}
func TestParserRejectsUnsafeYAMLAndBounds(t *testing.T) {
	for _, raw := range []string{"proxies: []\nproxies: []", "proxies: &x []\nx: *x", "proxies: !command []", "proxies: []\n---\nproxies: []", "proxies: [{name: x, name: y}]", strings.Repeat("a", MaxBytes+1)} {
		if _, err := Parse([]byte(raw)); err == nil || strings.Contains(err.Error(), raw[:min(8, len(raw))]) {
			t.Fatal("unsafe structure accepted or reflected")
		}
	}
}
func TestParserURISubscriptionAndSecrets(t *testing.T) {
	uri := "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-128-gcm:private-secret")) + "@node.example:443#Display"
	for _, raw := range []string{uri, base64.StdEncoding.EncodeToString([]byte(uri))} {
		nodes, err := Parse([]byte(raw))
		if err != nil || len(nodes) != 1 || !nodes[0].Supported || nodes[0].Name != "Display" {
			t.Fatalf("URI/base64 failed: %v", err)
		}
	}
	for _, raw := range []string{"proxies: [{name: Wrong, type: direct}]", "proxies: [{name: Wrong, type: trojan, server: node.example, port: 443, password: secret, tls: false}]", "proxies: [{name: Wrong, type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: secret}]"} {
		nodes, err := Parse([]byte(raw))
		if err != nil || len(nodes) != 1 || nodes[0].Supported {
			t.Fatal("dangerous node admitted")
		}
	}
}

func TestCanonicalTLSKeysMatchMihomoProtocolOptions(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	for _, typ := range []string{"http", "socks5", "trojan", "vmess", "vless"} {
		t.Run(typ, func(t *testing.T) {
			extra := ""
			switch typ {
			case "trojan":
				extra = ", password: secret"
			case "vmess", "vless":
				extra = ", uuid: " + uuid
			}
			nodes, err := Parse([]byte("proxies: [{name: TLS, type: " + typ + ", server: 8.8.8.8, port: 443, tls: true, sni: tls.example" + extra + "}]"))
			if err != nil || !nodes[0].Supported {
				t.Fatal("TLS fixture rejected", err)
			}
			key, wrong := "sni", "servername"
			if typ == "vmess" || typ == "vless" {
				key, wrong = "servername", "sni"
			}
			if nodes[0].Config[key] != "tls.example" || nodes[0].Config[wrong] != nil {
				t.Fatal("SNI lost by core protocol field mapping")
			}
		})
	}
}
func TestSafeTLSFalseAndReservedEndpointValidation(t *testing.T) {
	for _, value := range []string{"false", "true", "\"false\""} {
		nodes, e := Parse([]byte("proxies: [{name: TLS, type: http, server: node.example, port: 443, tls: true, skip-cert-verify: " + value + "}]"))
		if e != nil || nodes[0].Supported != (value == "false" || value == "true") {
			t.Fatal("boolean TLS setting was not honored or malformed data was accepted")
		}
	}
	for _, server := range []string{"100.64.1.1", "198.18.1.1", "192.0.2.1", "203.0.113.1"} {
		nodes, e := Parse([]byte("proxies: [{name: Reserved, type: http, server: " + server + ", port: 443}]"))
		if e != nil || nodes[0].Supported {
			t.Fatal("reserved server admitted")
		}
	}
}
func TestURINeverSilentlyChangesTransportOrPassword(t *testing.T) {
	raw := "ss://aes-128-gcm:p%2Bq%3Az@node.example:443#Label"
	nodes, e := Parse([]byte(raw))
	if e != nil || !nodes[0].Supported || nodes[0].Config["password"] != "p+q:z" {
		t.Fatal("URI password was altered")
	}
	for _, raw := range []string{"http://node.example:8080#Plain", "socks5://node.example:1080#Plain"} {
		nodes, e := Parse([]byte(raw))
		if e != nil || !nodes[0].Supported {
			t.Fatal("no-auth node rejected")
		}
	}
	for _, extra := range []string{"type=http", "type=tcp&path=/ignored", "type=tcp&host=ignored.example", "type=tcp&security=tls&unknown=secret", "type=tcp&bad=%ZZ"} {
		nodes, e := Parse([]byte("vless://12345678-1234-1234-1234-123456789abc@node.example:443?" + extra))
		if e != nil || nodes[0].Supported {
			t.Fatal("unsupported URI parameter was ignored")
		}
	}
}
func TestSSUserinfoAndNamesAreDecodedExactlyOnce(t *testing.T) {
	for _, raw := range []string{"ss://aes-128-gcm:p%2Bq%25%26%3Az@node.example:443#name%2520literal", "ss://" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p+q%&:z"))) + "@node.example:443#name%2520literal"} {
		nodes, e := Parse([]byte(raw))
		if e != nil || !nodes[0].Supported || nodes[0].Config["password"] != "p+q%&:z" || nodes[0].Name != "name%20literal" {
			t.Fatal("SS credentials or display label decoded incorrectly")
		}
	}
}

func TestParserRejectsResponseTextInsteadOfInventingUnsupportedNodes(t *testing.T) {
	for _, source := range []string{
		"error://subscription\nThis client is not allowed to fetch subscription",
		"<https://example.invalid/error>\n<html><body>private-response-marker</body></html>",
		"https://example.invalid:443\n<html>private-response-marker</html>",
		"ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-128-gcm:fictitious-password")) + "@node.example:443\nprivate-response-marker",
	} {
		nodes, e := Parse([]byte(source))
		if e == nil || len(nodes) != 0 || strings.Contains(e.Error(), "private-response-marker") {
			t.Fatal("non-node response was accepted or reflected")
		}
	}
}
func TestParserKeepsRecognizedSchemeAndSafeRejectionCategory(t *testing.T) {
	nodes, e := Parse([]byte("vless://12345678-1234-1234-1234-123456789abc@node.example:443?unsupported=fictitious-secret#Display\nhy2://fictitious-password@node.example:443#Other"))
	if e != nil || len(nodes) != 2 || nodes[0].Supported || nodes[1].Supported || nodes[0].Type != "vless" || nodes[1].Type != "hysteria2" {
		t.Fatal("URI rejection erased recognized scheme")
	}
	if nodes[0].Reason == nodes[1].Reason || strings.Contains(nodes[0].Reason, "fictitious-secret") || strings.Contains(nodes[1].Reason, "fictitious-password") {
		t.Fatal("URI and protocol failure categories were lost or exposed raw content")
	}
}
