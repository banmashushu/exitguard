package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func credentialService(t *testing.T) *Service {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	c.Mode, c.ProxyURL = "remote", "https://proxy.example:8443"
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	return s
}
func requireCredentialPersistence(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("private plaintext store supported on macOS")
	}
}
func rememberCredentials(t *testing.T, s *Service, username, password string, remember bool) error {
	t.Helper()
	setter, ok := any(s).(interface {
		SetProxyCredentialsWithRemember(string, string, bool) error
	})
	if !ok {
		t.Fatal("explicit plaintext remember operation missing")
	}
	return setter.SetProxyCredentialsWithRemember(username, password, remember)
}
func TestRememberedCredentialsRestoreClosedAndNeverEnterSnapshots(t *testing.T) {
	requireCredentialPersistence(t)
	s := credentialService(t)
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	path := s.configPath + ".credentials.json"
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private saved record missing: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err = json.Unmarshal(b, &record); err != nil {
		t.Fatal(err)
	}
	if record["version"] != float64(1) || record["proxyURL"] != "https://proxy.example:8443" || record["username"] != "fixture-user" || record["password"] != "fixture-password" {
		t.Fatal("saved record is not the requested endpoint-bound plaintext pair")
	}
	restored, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fields := statusFields(t, restored.Status())
	if fields["upstreamCredentialsSet"] != true || fields["upstreamCredentialsSaved"] != true || fields["upstreamCredentialsRestored"] != true {
		t.Fatalf("restored state not visible: %v", fields)
	}
	if restored.proxyUsername != "fixture-user" || restored.proxyPassword != "fixture-password" {
		t.Fatal("saved credentials not restored for matching endpoint")
	}
	if restored.Status().State != "unconfigured" || restored.armedIntent || restored.activeRoute != nil {
		t.Fatal("restoring credentials started admission or recovery")
	}
	snapshot, _ := json.Marshal([]any{restored.Config(), restored.Status(), restored.Events()})
	config, _ := os.ReadFile(s.configPath)
	for _, raw := range []string{string(snapshot), string(config)} {
		if strings.Contains(raw, "fixture-user") || strings.Contains(raw, "fixture-password") {
			t.Fatal("stored credentials leaked outside their record")
		}
	}
}
func TestSessionOnlyAndClearForgetRememberedCredentials(t *testing.T) {
	requireCredentialPersistence(t)
	for _, clear := range []bool{false, true} {
		t.Run(map[bool]string{false: "session-only", true: "clear"}[clear], func(t *testing.T) {
			s := credentialService(t)
			if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err != nil {
				t.Fatal(err)
			}
			username, password := "next-user", "next-password"
			if clear {
				username, password = "", ""
			}
			if err := s.SetProxyCredentials(username, password); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(s.configPath + ".credentials.json"); !os.IsNotExist(err) {
				t.Fatal("session-only/clear left a saved pair")
			}
			again, err := New(s.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if again.Status().UpstreamCredentialsSet || again.proxyUsername != "" {
				t.Fatal("forgotten pair restored after restart")
			}
		})
	}
}
func TestEndpointChangeForgetsSavedPairAndMismatchCannotRestore(t *testing.T) {
	requireCredentialPersistence(t)
	s := credentialService(t)
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(s.configPath + ".credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	c.ProxyURL = "https://different.example:9443"
	if err = s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(s.configPath + ".credentials.json"); !os.IsNotExist(err) {
		t.Fatal("endpoint change retained saved credentials")
	}
	if s.Status().UpstreamCredentialsSet {
		t.Fatal("endpoint change retained memory credentials")
	}
	if err = os.WriteFile(s.configPath+".credentials.json", saved, 0600); err != nil {
		t.Fatal(err)
	}
	again, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status().UpstreamCredentialsSet || again.proxyUsername != "" || again.Status().State == "proxy_active" {
		t.Fatal("mismatched pair restored")
	}
	if !strings.Contains(again.Status().Reason, "账户") {
		t.Fatal("mismatched storage needs sanitized visible guidance")
	}
}
func TestCredentialStorageFailuresRemainClosedAndCanBeReplaced(t *testing.T) {
	requireCredentialPersistence(t)
	for _, raw := range []string{"not-json", `{"version":1,"proxyURL":"https://proxy.example:8443","username":"fixture-user","password":"fixture-password","unknown":true}`, strings.Repeat("x", 8193)} {
		t.Run(raw[:8], func(t *testing.T) {
			s := credentialService(t)
			path := s.configPath + ".credentials.json"
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			again, err := New(s.configPath)
			if err != nil {
				t.Fatal("bad credential file prevented opening control panel")
			}
			if again.Status().UpstreamCredentialsSet || again.Status().State == "proxy_active" || strings.Contains(again.Status().Reason, "fixture-") {
				t.Fatal("invalid storage loaded or leaked")
			}
			if err := rememberCredentials(t, again, "replacement-user", "replacement-password", true); err != nil {
				t.Fatal(err)
			}
		})
	}
	s := credentialService(t)
	path := s.configPath + ".credentials.json"
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	s.status.State = "proxy_active"
	before := s.Status().SessionRevision
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err == nil {
		t.Fatal("save to nonregular target claimed success")
	}
	if s.Status().State != "blocked" || s.Status().SessionRevision == before || s.Status().UpstreamCredentialsSet {
		t.Fatal("failed store kept admission or accepted unsaved pair")
	}
	c := s.Config()
	c.ProxyURL = "https://different.example:9443"
	if err := s.SaveConfig(c); err == nil || s.Config().ProxyURL != "https://proxy.example:8443" {
		t.Fatal("failed credential removal committed a new endpoint")
	}
	if err := s.SetProxyCredentials("", ""); err == nil {
		t.Fatal("failed forget claimed success")
	}
}
func TestCredentialSymlinksAndLoosePermissionsAreRejected(t *testing.T) {
	requireCredentialPersistence(t)
	s := credentialService(t)
	path := s.configPath + ".credentials.json"
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err == nil {
		t.Fatal("saved through final symlink")
	}
	if err := s.SetProxyCredentials("", ""); err == nil {
		t.Fatal("unsafe symlink forget claimed success")
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "untouched" {
		t.Fatal("symlink referent modified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	again, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status().UpstreamCredentialsSet {
		t.Fatal("loose credential permissions accepted")
	}
	parentLink := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(filepath.Dir(s.configPath), parentLink); err != nil {
		t.Fatal(err)
	}
	linked, err := New(filepath.Join(parentLink, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rememberCredentials(t, linked, "fixture-user", "fixture-password", true); err == nil {
		t.Fatal("saved through linked credential directory")
	}
}
func TestUnsupportedPlatformsKeepSessionCredentialsUsable(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("non-mac behavior")
	}
	s := credentialService(t)
	if err := s.SetProxyCredentials("fixture-user", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	if !s.Status().UpstreamCredentialsSet {
		t.Fatal("session credentials unavailable")
	}
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err == nil {
		t.Fatal("unsupported private persistence claimed")
	}
}

func TestInvalidCredentialUpdateClearsRestoredStateAndKeepsDiskTruthful(t *testing.T) {
	requireCredentialPersistence(t)
	s := credentialService(t)
	if err := rememberCredentials(t, s, "fixture-user", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	restored, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.SetProxyCredentials("fixture-user", "bad\npassword"); err == nil {
		t.Fatal("invalid update accepted")
	}
	fields := statusFields(t, restored.Status())
	if fields["upstreamCredentialsRestored"] != false || fields["upstreamCredentialsSet"] != false || fields["upstreamCredentialsSaved"] != true {
		t.Fatal("invalid update left a misleading restored or saved state")
	}
	again, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Status().UpstreamCredentialsSet {
		t.Fatal("rejected input silently deleted remembered account")
	}
}

func TestCredentialRecordRejectsDuplicateEndpointAndAccountFields(t *testing.T) {
	requireCredentialPersistence(t)
	for _, duplicate := range []string{`"proxyURL":"https://other.example:9443",`, `"username":"other-user",`, `"password":"other-password",`, `"version":1,`} {
		t.Run(duplicate[:10], func(t *testing.T) {
			s := credentialService(t)
			raw := `{` + duplicate + `"version":1,"proxyURL":"https://proxy.example:8443","username":"fixture-user","password":"fixture-password"}`
			if err := os.WriteFile(s.configPath+".credentials.json", []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			again, err := New(s.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if again.Status().UpstreamCredentialsSet || again.Status().State != "blocked" {
				t.Fatal("ambiguous duplicate credential field restored")
			}
		})
	}
}
