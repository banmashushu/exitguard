package desktop

import (
	"strings"
	"testing"
)

// Rejecting a host containing URL syntax prevents an account, path or query
// from bypassing the separate protocol/host/port fields.
func TestProfileEndpointUsesOnlySeparateServerFields(t *testing.T) {
	for _, tc := range []struct{ protocol, host, port, want string }{
		{"SOCKS5", "proxy.example", "1080", "socks5://proxy.example:1080"},
		{"HTTPS", " 192.0.2.15 ", "443", "https://192.0.2.15:443"},
		{"HTTP", "Proxy.Example", "8080", "http://proxy.example:8080"},
	} {
		got, err := profileEndpoint(tc.protocol, tc.host, tc.port)
		if err != nil || got != tc.want {
			t.Fatalf("endpoint = %q, %v; want %q", got, err, tc.want)
		}
	}
	for _, host := range []string{"", "user:pass@proxy.example", "https://proxy.example", "proxy.example/path", "proxy.example?token=secret", "proxy.example#secret", "proxy.example:443", "256.1.1.1", "1.2.3", "proxy example", "-bad.example", "bad_.example", "[::1]", "proxy.example\\other"} {
		if got, err := profileEndpoint("HTTPS", host, "443"); err == nil {
			t.Errorf("accepted host %q as %q", host, got)
		}
	}
	for _, port := range []string{"", "0", "65536", "443/path", "+443", "04x"} {
		if _, err := profileEndpoint("HTTPS", "proxy.example", port); err == nil {
			t.Errorf("accepted port %q", port)
		}
	}
	if _, err := profileEndpoint("FTP", "proxy.example", "443"); err == nil {
		t.Fatal("accepted unsupported protocol")
	}
}

func TestSplitProfileEndpointRefusesSecretOrExtraURLParts(t *testing.T) {
	p, h, port, err := splitProfileEndpoint("socks5://proxy.example:1080")
	if err != nil || p != "SOCKS5" || h != "proxy.example" || port != "1080" {
		t.Fatalf("split = %q %q %q %v", p, h, port, err)
	}
	for _, raw := range []string{"https://u:secret@proxy.example:443", "https://proxy.example:443/", "https://proxy.example:443?secret=x", "https://proxy.example:443#secret"} {
		if _, _, _, err := splitProfileEndpoint(raw); err == nil {
			t.Fatal("accepted URL with account or extra components")
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("split error leaked input")
		}
	}
}
