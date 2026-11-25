package guard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"exitguard/internal/model"
)

// Dropping either hop's account, endpoint binding or revocation breaks this test.
func TestPreProxyProfileAccountsRemainIndependentAndPrivate(t *testing.T) {
	s := profileService(t)
	input := model.RemoteProfileInput{Name: "Chained", ProxyURL: "https://final.example:443", ExpectedIPs: []string{"203.0.113.7"}, CredentialAction: "replace", Username: "final-user-private", Password: "final-password-private", PreProxyURL: "socks5://127.0.0.1:1080", PreProxyUsername: "front-user-private", PreProxyPassword: "front-password-private"}
	p, err := s.SaveRemoteProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasPreProxyCredentials || p.PreProxyURL != "socks5://127.0.0.1:1080" {
		t.Fatal("first hop was not saved")
	}
	if err = s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if s.preProxyUsername != input.PreProxyUsername || s.proxyUsername != input.Username || s.Config().PreProxyURL != p.PreProxyURL {
		t.Fatal("hop account or endpoint mismatch")
	}
	restarted, err := New(s.configPath)
	if err != nil || restarted.preProxyPassword != input.PreProxyPassword || restarted.proxyPassword != input.Password || activeState(restarted.Status().State) {
		t.Fatalf("restart lost chain or activated it: %v", err)
	}
	data, _ := json.Marshal([]any{p, s.Config(), s.Status(), s.Events(), input})
	for _, secret := range []string{input.Username, input.Password, input.PreProxyUsername, input.PreProxyPassword} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private account escaped public output")
		}
	}
	input.ID, input.CredentialAction, input.Username, input.Password = p.ID, "keep", "", ""
	input.PreProxyUsername, input.PreProxyPassword = "", ""
	input.PreProxyURL = "http://other.example:8080"
	s.status.State, s.armedIntent = "proxy_active", true
	before := s.Status().SessionRevision
	if _, err = s.SaveRemoteProfile(input); err == nil {
		t.Fatal("changed first hop retained old account")
	}
	if activeState(s.Status().State) || s.armedIntent || s.Status().SessionRevision <= before {
		t.Fatal("invalid active edit did not revoke")
	}
	input.ClearPreProxyCredentials = true
	if _, err = s.SaveRemoteProfile(input); err != nil {
		t.Fatal(err)
	}
	if s.preProxyUsername != "" || s.proxyUsername != "final-user-private" {
		t.Fatal("clearing first account affected final account")
	}
	input.PreProxyUsername, input.PreProxyPassword = "front-next", "front-secret-next"
	input.ClearPreProxyCredentials = false
	if _, err = s.SaveRemoteProfile(input); err != nil {
		t.Fatal(err)
	}
	input.PreProxyURL, input.PreProxyUsername, input.PreProxyPassword = "", "", ""
	if _, err = s.SaveRemoteProfile(input); err != nil {
		t.Fatal(err)
	}
	if s.preProxyUsername != "" || s.preProxyPassword != "" || s.Config().PreProxyURL != "" {
		t.Fatal("disable retained hidden first hop")
	}
	cfg := s.Config()
	cfg.PreProxyURL = "http://bypass.example:8080"
	if err = s.SaveConfig(cfg); err == nil {
		t.Fatal("legacy config bypassed selected profile")
	}
}

// Existing strict v1 libraries must load; later writes must declare chain semantics.
func TestPreProxyProfileV1CompatibilityAndStrictV2(t *testing.T) {
	s := profileService(t)
	legacy := `{"version":1,"profiles":[{"id":"0123456789abcdef0123456789abcdef","name":"Legacy","proxyURL":"https://final.example:443","expectedIPs":[],"username":"","password":""}]}`
	if err := writeCredentialFile(s.configPath+".profiles.json", []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	profiles, err := s.RemoteProfiles()
	if err != nil || len(profiles) != 1 || profiles[0].PreProxyURL != "" {
		t.Fatalf("v1 failed: %v", err)
	}
	p := profiles[0]
	if _, err = s.SaveRemoteProfile(model.RemoteProfileInput{ID: p.ID, Name: p.Name, ProxyURL: p.ProxyURL, ExpectedIPs: []string{}, CredentialAction: "keep", PreProxyURL: "http://127.0.0.1:7890"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.configPath + ".profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		Version int `json:"version"`
	}
	json.Unmarshal(raw, &header)
	if header.Version != 3 {
		t.Fatal("chain stored in a format old readers may accept")
	}
	for _, bad := range []string{strings.Replace(string(raw), `"preProxyURL":`, `"unknown":`, 1), strings.Replace(string(raw), `"preProxyURL":"http://127.0.0.1:7890"`, `"preProxyURL":null`, 1), strings.Replace(string(raw), `"preProxyURL":`, `"preProxyURL":"","preProxyURL":`, 1)} {
		if err = writeCredentialFile(s.configPath+".profiles.json", []byte(bad)); err != nil {
			t.Fatal(err)
		}
		if _, err = readProfileLibrary(s.configPath + ".profiles.json"); err == nil {
			t.Fatal("malformed chain record accepted")
		}
	}
}

func TestPreProxyNormalizedEndpointKeepsOnlyItsBoundAccount(t *testing.T) {
	s := profileService(t)
	input := model.RemoteProfileInput{Name: "Normalized", ProxyURL: "https://FINAL.example:00443", CredentialAction: "replace", Username: "final-account", Password: "final-secret", PreProxyURL: "http://FRONT.example:08080", PreProxyUsername: "front-account", PreProxyPassword: "front-secret"}
	p, err := s.SaveRemoteProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProxyURL != "https://final.example:443" || p.PreProxyURL != "http://front.example:8080" {
		t.Fatal("saved endpoint was not normalized")
	}
	input.ID, input.ProxyURL, input.PreProxyURL = p.ID, "https://final.example:443", "http://front.example:8080"
	input.CredentialAction, input.Username, input.Password = "keep", "", ""
	input.PreProxyUsername, input.PreProxyPassword = "", ""
	if _, err = s.SaveRemoteProfile(input); err != nil {
		t.Fatal("normalized same endpoint lost account:", err)
	}
	if err = s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if s.preProxyUsername != "front-account" || s.proxyUsername != "final-account" {
		t.Fatal("normalization discarded or crossed accounts")
	}
}

func TestPreProxyNormalizedV1MigrationStillRecognizesLegacyPair(t *testing.T) {
	s := profileService(t)
	cfg := remoteConfig("https://FINAL.example:00443")
	cfg.ExpectedIPs = []string{"203.0.113.7"}
	if err := s.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProxyCredentialsWithRemember("legacy-account", "legacy-secret", true); err != nil {
		t.Fatal(err)
	}
	raw := `{"version":1,"profiles":[{"id":"0123456789abcdef0123456789abcdef","name":"Legacy","proxyURL":"https://FINAL.example:00443","expectedIPs":["203.0.113.7"],"username":"legacy-account","password":"legacy-secret"}]}`
	if err := writeCredentialFile(s.configPath+".profiles.json", []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRemoteProfiles(); err != nil {
		t.Fatal("equivalent normalized legacy pair was not recognized:", err)
	}
	if s.Config().ProxyURL != "" || s.proxyUsername != "" {
		t.Fatal("hidden legacy pair remained usable")
	}
	if err := s.SelectRemoteProfile("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if s.Config().ProxyURL != "https://final.example:443" || s.proxyUsername != "legacy-account" {
		t.Fatal("selected legacy profile lost normalized identity/account")
	}
}
