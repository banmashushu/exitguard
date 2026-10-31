package desktop

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exitguard/internal/guard"
)

func runtimeCore(t *testing.T, port uint16) *guard.Service {
	t.Helper()
	s, err := guard.New(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	c.ProxyPort = port
	if err = s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	return s
}
func freeListener(t *testing.T) net.Listener {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	return l
}

func TestDesktopRuntimeExposesNoWebControlAndClosesItsPort(t *testing.T) {
	l := freeListener(t)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	s := runtimeCore(t, port)
	r, err := StartService(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(2 * time.Second) })
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	for _, path := range []string{"/", "/app.js", "/api/snapshot"} {
		response, e := client.Get("http://" + s.Status().ProxyAddress + path)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusServiceUnavailable || strings.Contains(string(data), "token") || strings.Contains(string(data), "<html") {
			t.Fatalf("desktop exposed a control endpoint: %s %d", path, response.StatusCode)
		}
	}
	if !r.Close(2 * time.Second) {
		t.Fatal("guard did not stop")
	}
	if s.Status().State != "stopped" {
		t.Fatal("shutdown did not revoke admission")
	}
	rebound, e := net.Listen("tcp4", s.Status().ProxyAddress)
	if e != nil {
		t.Fatal("listener orphaned", e)
	}
	rebound.Close()
}

func TestDesktopPortConflictCannotBecomeAnIndependentSession(t *testing.T) {
	l := freeListener(t)
	defer l.Close()
	s := runtimeCore(t, uint16(l.Addr().(*net.TCPAddr).Port))
	if r, err := StartService(context.Background(), s); err == nil || r != nil {
		t.Fatal("conflicting desktop accepted port ownership")
	}
	if s.Status().State != "stopped" && s.Status().State != "blocked" {
		t.Fatal("port failure did not close admission")
	}
}
