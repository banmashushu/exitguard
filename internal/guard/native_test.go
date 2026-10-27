package guard

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"

	"exitguard/internal/model"
)

func TestNativePreviewRejectsStaleAndStrictSessions(t *testing.T) {
	s := &Service{config: model.Config{EnforcementMode: "proxy-only", ProxyPort: 17890}, status: model.Status{State: "proxy_active", EnforcementMode: "proxy-only", ProxyAddress: "127.0.0.1:17890", SessionRevision: 3}, running: true}
	prepared := false
	s.prepareNative = func(context.Context, string, string) (*exec.Cmd, error) {
		prepared = true
		s.mu.Lock()
		s.status.SessionRevision++
		s.mu.Unlock()
		return exec.Command(filepath.Join(t.TempDir(), "must-not-run")), nil
	}
	if err := s.LaunchNativePreview(context.Background(), "chrome", `C:\Apps\chrome.exe`, 3, true); err == nil {
		t.Fatal("accepted changed session")
	}
	if !prepared {
		t.Fatal("did not reach external native preparation")
	}
	prepared = false
	s.config.EnforcementMode = "required"
	if err := s.LaunchNativePreview(context.Background(), "chrome", `C:\Apps\chrome.exe`, 4, true); err == nil || prepared {
		t.Fatal("required mode silently downgraded")
	}
}

func TestNativePreviewNeverFallsBackOrClaimsArmed(t *testing.T) {
	s := &Service{config: model.Config{EnforcementMode: "proxy-only", ProxyPort: 17890}, status: model.Status{State: "proxy_active", EnforcementMode: "proxy-only", ProxyAddress: "127.0.0.1:17890", SessionRevision: 2}, running: true}
	calls := 0
	s.prepareNative = func(context.Context, string, string) (*exec.Cmd, error) {
		calls++
		return exec.Command(filepath.Join(t.TempDir(), "missing-Start.exe")), nil
	}
	if err := s.LaunchNativePreview(context.Background(), "chrome", `C:\Apps\chrome.exe`, 2, false); err == nil || calls != 0 {
		t.Fatal("preview acknowledgement missing")
	}
	if err := s.LaunchNativePreview(context.Background(), "chrome", `C:\Apps\chrome.exe`, 2, true); err == nil {
		t.Fatal("missing runtime executable should fail")
	}
	if calls != 1 || s.Status().State != "proxy_active" || s.Status().FilterActive {
		t.Fatal("fallback or full protection claim")
	}
}
