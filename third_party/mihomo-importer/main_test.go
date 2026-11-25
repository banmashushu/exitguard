// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func encoded(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func TestNativeConversionCommonProtocolsAndTrojanMetadata(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	vmess, _ := json.Marshal(map[string]any{"v": "2", "ps": "fixture", "add": "node.invalid", "port": "443", "id": uuid, "aid": "0", "net": "tcp", "type": "none", "tls": "tls", "sni": "tls.invalid"})
	for _, tc := range []struct{ line, typ string }{
		{"trojan://fictitious-password@node.invalid:443?allowInsecure=0&peer=tls.invalid&sni=tls.invalid&type=tcp&provider-metadata=accepted-natively", "trojan"},
		{"ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-128-gcm:fictitious-password")) + "@node.invalid:443#fixture", "ss"},
		{"ssr://" + encoded("node.invalid:443:origin:aes-128-cfb:plain:"+encoded("fictitious-password")+"/?remarks="+encoded("fixture")), "ssr"},
		{"vmess://" + base64.RawStdEncoding.EncodeToString(vmess), "vmess"},
		{"vless://" + uuid + "@node.invalid:443?security=reality&pbk=fictitious-public-key&sid=1234&type=tcp", "vless"},
		{"hy2://fictitious-password@node.invalid:443?sni=tls.invalid", "hysteria2"},
		{"tuic://" + uuid + ":fictitious-password@node.invalid:443?sni=tls.invalid", "tuic"},
		{"anytls://fictitious-password@node.invalid:443?sni=tls.invalid", "anytls"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			r := convertLine(tc.line)
			if r.Error != "" || r.Config["type"] != tc.typ || r.Config["server"] != "node.invalid" {
				t.Fatal("native conversion fixture rejected or changed")
			}
			if r.Config["password"] == "" && tc.typ == "trojan" {
				t.Fatal("authentication discarded")
			}
		})
	}
}
func TestNativeGeneratedDefaultsStableAndPinPreserved(t *testing.T) {
	line := "trojan://fictitious-password@node.invalid:443?type=ws&path=/fixture&sni=tls.invalid&pcs=fictitious-pin&fp=firefox"
	first := convertLine(line)
	if first.Error != "" {
		t.Fatal("fixture rejected")
	}
	a, _ := json.Marshal(first)
	for i := 0; i < 12; i++ {
		b, _ := json.Marshal(convertLine(line))
		if !bytes.Equal(a, b) {
			t.Fatal("identical import changed generated defaults")
		}
	}
	if first.Config["fingerprint"] != "fictitious-pin" || first.Config["client-fingerprint"] != "firefox" || first.Config["sni"] != "tls.invalid" {
		t.Fatal("native pin/auth options changed")
	}
}
func TestExactOneResultAndMalformedInputNoReflection(t *testing.T) {
	lines := []string{"trojan://bad%ZZ", "vless://fictitious-private-detail", "unknown://fictitious-private-detail"}
	request, _ := json.Marshal(map[string]any{"version": 1, "lines": lines})
	var out bytes.Buffer
	if code := run(bytes.NewReader(request), &out); code != 0 {
		t.Fatal("valid IPC envelope failed")
	}
	if strings.Contains(out.String(), "fictitious-private-detail") {
		t.Fatal("conversion error leaked raw input")
	}
	var response struct {
		Version int          `json:"version"`
		Results []conversion `json:"results"`
	}
	if json.Unmarshal(out.Bytes(), &response) != nil || len(response.Results) != len(lines) {
		t.Fatal("line count changed")
	}
	for _, r := range response.Results {
		if r.Error != "invalid_uri" || len(r.Config) != 0 {
			t.Fatal("invalid line not represented by fixed error")
		}
	}
}
func TestStrictBoundedIPC(t *testing.T) {
	for _, raw := range []string{`{"version":2,"lines":[]}`, `{"version":1,"lines":[],"unknown":"private"}`, `{"version":1,"lines":[]} {}`, `{"version":1,"version":1,"lines":[]}`} {
		var out bytes.Buffer
		if run(strings.NewReader(raw), &out) == 0 || out.Len() != 0 {
			t.Fatal("invalid envelope accepted or reflected")
		}
	}
}

func TestEncodedSSAuthenticationAndDisplayDecodeExactlyOnce(t *testing.T) {
	for _, line := range []string{
		"ss://aes-128-gcm:p%2Bq%25%26%3Az@node.invalid:443#name%2520literal",
		"ss://" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p+q%&:z"))) + "@node.invalid:443#name%2520literal",
	} {
		r := convertLine(line)
		if r.Error != "" || r.Config["password"] != "p+q%&:z" || r.Config["name"] != "name%20literal" {
			t.Fatal("native SS conversion changed credentials or display encoding")
		}
	}
}

func TestNativeHTTPUpgradeDefaultsStable(t *testing.T) {
	line := "vless://12345678-1234-1234-1234-123456789abc@node.invalid:443?security=tls&type=httpupgrade&host=authority.invalid&path=/fixture"
	a := convertLine(line)
	if a.Error != "" {
		t.Fatal("fixture rejected")
	}
	first, _ := json.Marshal(a)
	for i := 0; i < 8; i++ {
		next, _ := json.Marshal(convertLine(line))
		if !bytes.Equal(first, next) {
			t.Fatal("native httpupgrade generated defaults changed")
		}
	}
}

func TestConversionPanicBecomesFixedPrivateFailure(t *testing.T) {
	result := convertLineWith("fictitious-private-uri", func([]byte) ([]map[string]any, error) { panic("fictitious-private-panic") })
	if result.Error != "invalid_uri" || len(result.Config) != 0 {
		t.Fatal("panic escaped the private conversion boundary")
	}
}
