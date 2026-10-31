package desktop

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exitguard/internal/guard"
)

type observedProfileStartup struct {
	*guard.Service
	called    bool
	portOwned bool
}

func (s *observedProfileStartup) EnsureRemoteProfiles() error {
	s.called = true
	l, err := net.Listen("tcp4", s.Status().ProxyAddress)
	s.portOwned = err != nil
	if l != nil {
		l.Close()
	}
	return s.Service.EnsureRemoteProfiles()
}

func TestProfileMigrationRunsOnlyAfterListenerOwnershipAndLeavesClosed(t *testing.T) {
	l := freeListener(t)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	s := &observedProfileStartup{Service: runtimeCore(t, port)}
	config := s.Config()
	config.Mode = "remote"
	config.ProxyURL = "https://legacy.example:443"
	config.ExpectedIPs = nil
	if err := s.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProxyCredentialsWithRemember("legacy-user", "legacy-password", true); err != nil {
		t.Fatal(err)
	}
	r, profiles, err := startDesktopService(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(time.Second)
	if !s.called || !s.portOwned || len(profiles) != 1 || !profiles[0].HasCredentials || s.Config().RemoteProfileID != profiles[0].ID || s.Status().State == "proxy_active" || s.Status().State == "armed" {
		t.Fatal("startup failed to migrate after ownership while leaving forwarding closed")
	}
}

func TestConflictingListenerPreventsProfileMigration(t *testing.T) {
	l := freeListener(t)
	defer l.Close()
	s := &observedProfileStartup{Service: runtimeCore(t, uint16(l.Addr().(*net.TCPAddr).Port))}
	r, _, err := startDesktopService(context.Background(), s)
	if err == nil || r != nil || s.called {
		t.Fatal("conflicting startup migrated before owning its listener")
	}
}

func TestProfileLibraryFailureClosesOwnedListenerAndRedactsFailure(t *testing.T) {
	l := freeListener(t)
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := guard.New(path)
	if err != nil {
		t.Fatal(err)
	}
	config := s.Config()
	config.ProxyPort = port
	if err = s.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".profiles.json", []byte(`{"password":"never-show-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := startDesktopService(context.Background(), s)
	if err == nil || r != nil || strings.Contains(err.Error(), "never-show-secret") {
		t.Fatal("invalid library did not block startup safely")
	}
	rebound, err := net.Listen("tcp4", s.Status().ProxyAddress)
	if err != nil {
		t.Fatal("failed profile initialization left listener open", err)
	}
	rebound.Close()
}
