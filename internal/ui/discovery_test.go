package ui

import (
	"encoding/json"
	"testing"
)

func TestDesktopDiscoveryAPIIsAuthenticatedReadOnlyAndTyped(t *testing.T) {
	h, _ := testHandler()
	if w := request(h, "GET", "/api/apps", "", "", h.host, ""); w.Code != 401 {
		t.Fatal("unauthenticated application inventory accepted")
	}
	w := request(h, "GET", "/api/apps", "", "test-token", h.host, "")
	if w.Code != 200 {
		t.Fatalf("application discovery unavailable: %d", w.Code)
	}
	var response struct {
		Apps []struct{ Kind, Name, Path, BundleID string } `json:"apps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, app := range response.Apps {
		if (app.Kind != "browser" && app.Kind != "claude") || app.Name == "" || app.Path == "" {
			t.Fatal("untyped or incomplete desktop candidate")
		}
	}
	if w := request(h, "POST", "/api/apps", "{}", "test-token", h.host, ""); w.Code != 405 {
		t.Fatal("discovery accepted a mutation request")
	}
}
