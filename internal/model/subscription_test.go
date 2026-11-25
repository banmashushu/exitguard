package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSubscriptionInputNeverSerializesItsSource(t *testing.T) {
	b, _ := json.Marshal(SubscriptionInput{Name: "Local", URL: "https://source.example/token-private", Content: []byte("private-node-password")})
	if strings.Contains(string(b), "private") {
		t.Fatal("private subscription source escaped input DTO")
	}
}
func TestSubscriptionDownloadRouteIsPublicWithoutSource(t *testing.T) {
	input := SubscriptionInput{Name: "Fictitious", URL: "https://source.example/private-token", DownloadRoute: "active_exitguard"}
	b, _ := json.Marshal(input)
	if !strings.Contains(string(b), `"downloadRoute":"active_exitguard"`) || strings.Contains(string(b), "private-token") {
		t.Fatal("download route or source redaction contract changed")
	}
}
