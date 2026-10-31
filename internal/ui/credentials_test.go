package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"exitguard/internal/guard"
)

func TestRememberCredentialAPIRequiresExplicitChoiceAndKeepsSecretsOut(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Mac private persistence")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	service, err := guard.New(path)
	if err != nil {
		t.Fatal(err)
	}
	c := service.Config()
	c.ProxyURL = "https://proxy.example:8443"
	if err = service.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	h := &handler{service: service, host: "127.0.0.1:12345", token: "test-token"}
	w := request(h, "POST", "/api/proxy-credentials", `{"username":"api-fixture-user","password":"api-fixture-password","remember":true}`, "test-token", h.host, "")
	if w.Code != 200 {
		t.Fatalf("remember unavailable: %d", w.Code)
	}
	if _, err = os.Stat(path + ".credentials.json"); err != nil {
		t.Fatal("remember request did not persist")
	}
	for _, raw := range []string{w.Body.String(), snapshotBody(t, h)} {
		if strings.Contains(raw, "api-fixture-") {
			t.Fatal("credential API reflected saved pair")
		}
	}
	w = request(h, "POST", "/api/proxy-credentials", `{"username":"session-user","password":"session-password","remember":false}`, "test-token", h.host, "")
	if w.Code != 200 {
		t.Fatalf("session-only request failed: %d", w.Code)
	}
	if _, err = os.Stat(path + ".credentials.json"); !os.IsNotExist(err) {
		t.Fatal("explicit session-only request did not forget old record")
	}
	w = request(h, "POST", "/api/proxy-credentials", `{"username":"","password":"","remember":true}`, "test-token", h.host, "")
	if w.Code != 400 {
		t.Fatal("blank save could accidentally clear restored credentials")
	}
	w = request(h, "POST", "/api/clear-proxy-credentials", `{}`, "test-token", h.host, "")
	if w.Code != 200 || service.Status().UpstreamCredentialsSet {
		t.Fatal("explicit clear action unavailable")
	}
	if w = request(h, "POST", "/api/clear-proxy-credentials", `{}`, "", h.host, ""); w.Code != 401 {
		t.Fatal("unauthenticated clear accepted")
	}
	if err = os.Mkdir(path+".credentials.json", 0700); err != nil {
		t.Fatal(err)
	}
	w = request(h, "POST", "/api/proxy-credentials", `{"username":"api-fixture-user","password":"api-fixture-password","remember":true}`, "test-token", h.host, "")
	if w.Code == 200 || strings.Contains(w.Body.String(), "api-fixture-") || !strings.Contains(w.Body.String(), "保存") {
		t.Fatal("store error was unsafe or misreported as success/format only")
	}
}
func snapshotBody(t *testing.T, h *handler) string {
	t.Helper()
	w := request(h, "GET", "/api/snapshot", "", "test-token", h.host, "")
	if !json.Valid(w.Body.Bytes()) {
		t.Fatal("invalid snapshot")
	}
	return w.Body.String()
}
