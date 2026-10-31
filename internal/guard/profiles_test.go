package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"exitguard/internal/model"
)

func profileService(t *testing.T) *Service {
	t.Helper()
	requireCredentialPersistence(t)
	s, err := New(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func saveProfile(t *testing.T, s *Service, name, endpoint, username string) model.RemoteProfile {
	t.Helper()
	action, password := "clear", ""
	if username != "" {
		action, password = "replace", "fixture-password-"+username
	}
	p, err := s.SaveRemoteProfile(model.RemoteProfileInput{Name: name, ProxyURL: endpoint, ExpectedIPs: []string{"203.0.113.7"}, CredentialAction: action, Username: username, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A switch must change the identity as well as the endpoint: two accounts on
// the same server may have different independent fixed exits.
func TestRemoteProfileSwitchKeepsSameEndpointAccountsIndependent(t *testing.T) {
	s := profileService(t)
	a := saveProfile(t, s, "First", "https://proxy.example:8443", "fixture-account-a")
	b := saveProfile(t, s, "Second", "https://proxy.example:8443", "fixture-account-b")
	if a.ID == "" || a.ID == b.ID || s.Config().RemoteProfileID != "" {
		t.Fatal("creation selected a profile or failed to assign independent IDs")
	}
	for _, selected := range []model.RemoteProfile{a, b, a} {
		s.status.State, s.armedIntent = "proxy_active", true
		before := s.Status().SessionRevision
		if err := s.SelectRemoteProfile(selected.ID); err != nil {
			t.Fatal(err)
		}
		wantUsername := map[string]string{a.ID: "fixture-account-a", b.ID: "fixture-account-b"}[selected.ID]
		if s.proxyUsername != wantUsername || s.proxyPassword != "fixture-password-"+wantUsername || s.Config().RemoteProfileID != selected.ID {
			t.Fatal("selected endpoint inherited another profile's pair")
		}
		if activeState(s.Status().State) || s.armedIntent || s.Status().SessionRevision <= before {
			t.Fatal("switch preserved forwarding or recovery intent")
		}
	}
	restarted, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Config().RemoteProfileID != a.ID || restarted.proxyUsername != "fixture-account-a" || activeState(restarted.Status().State) || restarted.armedIntent {
		t.Fatal("restart lost selected identity or restored forwarding")
	}
	profiles, err := restarted.RemoteProfiles()
	if err != nil || len(profiles) != 2 || !profiles[0].HasCredentials {
		t.Fatalf("saved profiles unavailable: %v", err)
	}
	snapshot, _ := json.Marshal([]any{profiles, restarted.Config(), restarted.Status(), restarted.Events(), model.RemoteProfileInput{Username: "fixture-account-a", Password: "fixture-password-fixture-account-a"}})
	if strings.Contains(string(snapshot), "fixture-account") || strings.Contains(string(snapshot), "fixture-password") {
		t.Fatal("credentials leaked through a public DTO or snapshot")
	}
}

func TestActiveProfileEditingRejectsCredentialsAtChangedEndpoint(t *testing.T) {
	s := profileService(t)
	p := saveProfile(t, s, "Saved", "https://proxy.example:8443", "fixture-account-a")
	if err := s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	input := model.RemoteProfileInput{ID: p.ID, Name: p.Name, ProxyURL: "socks5://other.example:1080", ExpectedIPs: []string{"203.0.113.8"}, CredentialAction: "keep"}
	if _, err := s.SaveRemoteProfile(input); err == nil {
		t.Fatal("endpoint change reused the former account")
	}
	if activeState(s.Status().State) || s.armedIntent || s.Config().ProxyURL != "https://proxy.example:8443" {
		t.Fatal("rejected edit kept forwarding or changed the selected endpoint")
	}
	input.CredentialAction = "clear"
	if _, err := s.SaveRemoteProfile(input); err != nil {
		t.Fatal(err)
	}
	if s.Config().ProxyURL != "socks5://other.example:1080" || s.proxyUsername != "" || s.Status().UpstreamCredentialsSet {
		t.Fatal("active edit failed to replace all effective profile fields")
	}
	restarted, err := New(s.configPath)
	if err != nil || restarted.Config().ProxyURL != "socks5://other.example:1080" || restarted.proxyUsername != "" {
		t.Fatalf("startup trusted stale parameters in config instead of profile source: %v", err)
	}
	c := s.Config()
	c.ProxyURL = "https://wrong.example:9443"
	if err := s.SaveConfig(c); err == nil {
		t.Fatal("legacy config update changed the endpoint of a selected profile")
	}
	if err := s.SetProxyCredentials("another", "account"); err == nil {
		t.Fatal("legacy credential setter bypassed selected profile storage")
	}
}

func TestDeleteInactiveProfilePreservesSessionAndActiveDeleteCannotRestore(t *testing.T) {
	s := profileService(t)
	a := saveProfile(t, s, "Active", "https://proxy.example:8443", "fixture-account-a")
	b := saveProfile(t, s, "Inactive", "http://other.example:8080", "fixture-account-b")
	if err := s.SelectRemoteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	before := s.Status().SessionRevision
	if err := s.DeleteRemoteProfile(b.ID); err != nil {
		t.Fatal(err)
	}
	if !activeState(s.Status().State) || s.Status().SessionRevision != before || !s.armedIntent {
		t.Fatal("deleting an unrelated profile interrupted the current session")
	}
	if err := s.DeleteRemoteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	if s.Config().RemoteProfileID != "" || s.Config().ProxyURL != "" || len(s.Config().ExpectedIPs) != 0 || s.proxyUsername != "" || activeState(s.Status().State) || s.armedIntent {
		t.Fatal("active deletion retained usable routing or credentials")
	}
	restarted, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := restarted.RemoteProfiles()
	if err != nil || len(profiles) != 0 || restarted.Config().ProxyURL != "" || restarted.proxyUsername != "" {
		t.Fatal("deleted selected profile came back after restart")
	}
}

func TestRemoteProfilesRejectLimitAndMalformedOrAmbiguousPrivateRecords(t *testing.T) {
	s := profileService(t)
	for i := 0; i < 32; i++ {
		saveProfile(t, s, fmt.Sprint("Profile ", i), "https://proxy.example:8443", "")
	}
	profiles, err := s.RemoteProfiles()
	if err != nil || len(profiles) != 32 {
		t.Fatalf("could not retain all independent profiles: %v", err)
	}
	if err := s.SelectRemoteProfile(profiles[0].ID); err != nil {
		t.Fatal(err)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	before := s.Status()
	if _, err := s.SaveRemoteProfile(model.RemoteProfileInput{Name: "Overflow", ProxyURL: "https://proxy.example:8443", CredentialAction: "clear"}); err == nil {
		t.Fatal("33rd profile saved")
	}
	if !reflect.DeepEqual(before, s.Status()) || !s.armedIntent {
		t.Fatal("profile count limit interrupted an unrelated selected session")
	}
	valid := `{"version":1,"profiles":[{"id":"0123456789abcdef0123456789abcdef","name":"Saved","proxyURL":"https://proxy.example:8443","expectedIPs":["203.0.113.7"],"username":"fixture-account","password":"fixture-password"}]}`
	for _, raw := range []string{
		`null`, `{"version":1,"profiles":null}`, `{"version":1,"version":1,"profiles":[]}`,
		strings.Replace(valid, `"name":"Saved"`, `"name":"Saved","name":"other"`, 1),
		strings.Replace(valid, `"password":"fixture-password"`, `"password":null`, 1),
		strings.Replace(valid, `,"password":"fixture-password"`, ``, 1),
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"name":"Saved"`, `"unknown":true,"name":"Saved"`, 1),
		strings.Replace(valid, `"expectedIPs":["203.0.113.7"]`, `"expectedIPs":null`, 1),
		strings.TrimSuffix(valid, `]}`) + `,` + strings.TrimSuffix(strings.TrimPrefix(valid, `{"version":1,"profiles":[`), `]}`) + `]}`,
		strings.Repeat("x", (128<<10)+1),
	} {
		t.Run(fmt.Sprint(len(raw), raw[:min(20, len(raw))]), func(t *testing.T) {
			if err := writeCredentialFile(s.configPath+".profiles.json", []byte(raw)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RemoteProfiles(); err == nil || strings.Contains(err.Error(), "fixture-") {
				t.Fatal("invalid private library accepted or exposed its content")
			}
		})
	}
}

func TestMissingSelectedLibraryNeverRestoresLegacyCredentials(t *testing.T) {
	s := profileService(t)
	p := saveProfile(t, s, "Selected", "https://proxy.example:8443", "fixture-profile")
	if err := s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if err := writeCredentialRecord(s.configPath+".credentials.json", credentialRecord{Version: 1, ProxyURL: "https://proxy.example:8443", Username: "fixture-legacy", Password: "fixture-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.configPath + ".profiles.json"); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.proxyUsername != "" || restarted.Config().ProxyURL != "" || restarted.Status().State != "blocked" {
		t.Fatal("selected profile absence fell back to stale config or legacy credentials")
	}
	restarted.makeRemoteRoute = func(context.Context, model.Config, string, string) (route, error) {
		t.Fatal("missing selected library attempted remote route construction")
		return nil, nil
	}
	if err := restarted.Check(context.Background()); err == nil {
		t.Fatal("missing selected library allowed validation")
	}
}

func TestRemoteProfileLegacyMigrationIsOnceAndPreservesSavedCredentials(t *testing.T) {
	requireCredentialPersistence(t)
	path := filepath.Join(t.TempDir(), "config.json")
	c := remoteConfig("https://proxy.example:8443")
	c.ExpectedIPs = []string{"203.0.113.7"}
	if err := persistConfig(path, c); err != nil {
		t.Fatal(err)
	}
	if err := writeCredentialRecord(path+".credentials.json", credentialRecord{Version: 1, ProxyURL: c.ProxyURL, Username: "fixture-legacy", Password: "fixture-secret"}); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	profiles, err := s.RemoteProfiles()
	if err != nil || len(profiles) != 1 || profiles[0].Name != "当前代理" || s.Config().RemoteProfileID != profiles[0].ID || s.proxyUsername != "fixture-legacy" || activeState(s.Status().State) {
		t.Fatalf("legacy setup was not migrated as a closed independent profile: %v", err)
	}
	if _, err := os.Stat(path + ".credentials.json"); !os.IsNotExist(err) {
		t.Fatal("completed migration left an abandoned legacy password copy")
	}
	again, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	second, err := again.RemoteProfiles()
	if err != nil || !reflect.DeepEqual(second, profiles) {
		t.Fatal("startup migration duplicated or overwrote the profile library")
	}
}

func TestInactiveProfileInputErrorsNeverInterruptSelectedSession(t *testing.T) {
	s := profileService(t)
	a := saveProfile(t, s, "Active", "https://proxy.example:8443", "fixture-active")
	b := saveProfile(t, s, "Inactive", "https://other.example:8443", "fixture-inactive")
	if err := s.SelectRemoteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	before := s.Status()
	for _, input := range []model.RemoteProfileInput{
		{ID: b.ID, Name: "Bad", ProxyURL: "bad-endpoint", CredentialAction: "keep"},
		{ID: "not-an-existing-profile", Name: "Bad", ProxyURL: b.ProxyURL, CredentialAction: "clear"},
		{Name: "", ProxyURL: b.ProxyURL, CredentialAction: "clear"},
	} {
		if _, err := s.SaveRemoteProfile(input); err == nil {
			t.Fatal("invalid inactive input accepted")
		}
		if !reflect.DeepEqual(before, s.Status()) || !s.armedIntent || s.proxyUsername != "fixture-active" {
			t.Fatal("inactive input error interrupted the selected session")
		}
	}
	if err := s.DeleteRemoteProfile("not-an-existing-profile"); err == nil {
		t.Fatal("unknown deletion claimed success")
	}
	if !reflect.DeepEqual(before, s.Status()) || !s.armedIntent {
		t.Fatal("unknown inactive deletion interrupted the selected session")
	}
}

func TestProfileCutoverCleanupFailureCanRetryWithoutLosingNewCredentials(t *testing.T) {
	s := profileService(t)
	p := saveProfile(t, s, "Saved", "https://proxy.example:8443", "fixture-current")
	legacyPath := s.configPath + ".credentials.json"
	// An unsafe legacy target cannot be silently removed. Selection can be
	// durable before cleanup fails; the new private source must remain intact.
	if err := os.Mkdir(legacyPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.SelectRemoteProfile(p.ID); err == nil {
		t.Fatal("cutover ignored a failed old-account cleanup")
	}
	if s.Config().RemoteProfileID != p.ID || s.proxyUsername != "fixture-current" || s.Status().State != "blocked" || s.armedIntent {
		t.Fatal("cleanup failure lost the durable new identity or left forwarding enabled")
	}
	if err := os.Remove(legacyPath); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	if s.Config().RemoteProfileID != p.ID || s.proxyUsername != "fixture-current" || activeState(s.Status().State) || s.armedIntent || s.Status().State == "blocked" {
		t.Fatal("cleanup retry did not recover the selected source while keeping it closed")
	}
	if _, err := s.SaveRemoteProfile(model.RemoteProfileInput{ID: p.ID, Name: p.Name, ProxyURL: p.ProxyURL, ExpectedIPs: p.ExpectedIPs, CredentialAction: "clear"}); err != nil {
		t.Fatal(err)
	}
	lib, err := readProfileLibrary(s.configPath + ".profiles.json")
	if err != nil || lib.Profiles[0].Username != "" || lib.Profiles[0].Password != "" {
		t.Fatal("clear retained a saved account in the authoritative profile")
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatal("clear left an abandoned legacy account copy")
	}
	if err := s.DeleteRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatal("delete left an abandoned legacy account copy")
	}
}

func TestProfileSelectionFailureRetainsConsistentOldPairAcrossRestart(t *testing.T) {
	s := profileService(t)
	a := saveProfile(t, s, "First", "https://first.example:8443", "fixture-first")
	b := saveProfile(t, s, "Second", "https://second.example:9443", "fixture-second")
	if err := s.SelectRemoteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	configBackup := s.configPath + ".fixture-backup"
	if err := os.Rename(s.configPath, configBackup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.configPath, 0700); err != nil {
		t.Fatal(err)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	if err := s.SelectRemoteProfile(b.ID); err == nil {
		t.Fatal("failed selection claimed successful persistence")
	}
	if s.Config().RemoteProfileID != a.ID || s.Config().ProxyURL != "https://first.example:8443" || s.proxyUsername != "fixture-first" || activeState(s.Status().State) || s.armedIntent {
		t.Fatal("failed config reference write changed or reopened old pair")
	}
	if err := os.Remove(s.configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(configBackup, s.configPath); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(s.configPath)
	if err != nil || restarted.Config().RemoteProfileID != a.ID || restarted.proxyUsername != "fixture-first" || activeState(restarted.Status().State) {
		t.Fatalf("failed switch did not restart with its original consistent pair: %v", err)
	}
}

func TestProfileWriteFailuresKeepPrivateRecordsAndRevokeCurrentSession(t *testing.T) {
	s := profileService(t)
	p := saveProfile(t, s, "Saved", "https://proxy.example:8443", "fixture-user")
	if err := s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	path := s.configPath + ".profiles.json"
	backup := path + ".fixture-backup"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	s.status.State, s.armedIntent = "proxy_active", true
	if _, err := s.SaveRemoteProfile(model.RemoteProfileInput{ID: p.ID, Name: "Changed", ProxyURL: p.ProxyURL, ExpectedIPs: p.ExpectedIPs, CredentialAction: "replace", Username: "fixture-new", Password: "fixture-new-password"}); err == nil {
		t.Fatal("unwritable profile target accepted a credential replacement")
	}
	if activeState(s.Status().State) || s.armedIntent || s.proxyUsername == "fixture-new" {
		t.Fatal("profile write failure kept forwarding or accepted the unsaved account")
	}
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("failed library update allowed a new check using uncertain data")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(s.configPath)
	if err != nil || restarted.proxyUsername != "fixture-user" || restarted.Config().RemoteProfileID != p.ID {
		t.Fatalf("failed write discarded the former private record: %v", err)
	}
}

func TestProfileDetachAndDraftMigrationNeverSelectDeletedOrUnexpectedProfile(t *testing.T) {
	s := profileService(t)
	c := s.Config()
	c.ProxyURL = "https://legacy.example:8443"
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProxyCredentialsWithRemember("fixture-draft", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	profiles, err := s.RemoteProfiles()
	if err != nil || len(profiles) != 1 || !profiles[0].HasCredentials || len(profiles[0].ExpectedIPs) != 0 || s.Config().RemoteProfileID == "" {
		t.Fatal("legacy remote without expected IP was lost instead of preserved as a draft")
	}
	if err := s.SelectRemoteProfile(""); err != nil {
		t.Fatal(err)
	}
	if s.Config().RemoteProfileID != "" || s.Config().ProxyURL != "" || s.proxyUsername != "" || activeState(s.Status().State) {
		t.Fatal("explicit cancellation retained a usable active route")
	}
	if err := s.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	after, err := s.RemoteProfiles()
	if err != nil || !reflect.DeepEqual(after, profiles) || s.Config().RemoteProfileID != "" {
		t.Fatal("initialization overwrote, duplicated or silently selected the existing library")
	}
}

func TestLegacyMigrationConfigWriteFailureLeavesBothSourcesRecoverable(t *testing.T) {
	s := profileService(t)
	c := s.Config()
	c.ProxyURL, c.ExpectedIPs = "https://legacy.example:8443", []string{"203.0.113.7"}
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProxyCredentialsWithRemember("fixture-original", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	backup := s.configPath + ".fixture-backup"
	if err := os.Rename(s.configPath, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.configPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRemoteProfiles(); err == nil {
		t.Fatal("migration claimed success after failing to persist its selected identity")
	}
	if s.Config().RemoteProfileID != "" || s.proxyUsername != "fixture-original" || s.Status().State != "blocked" || s.armedIntent {
		t.Fatal("failed migration lost old runtime or kept forwarding")
	}
	lib, err := readProfileLibrary(s.configPath + ".profiles.json")
	if err != nil || len(lib.Profiles) != 1 || lib.Profiles[0].Username != "fixture-original" {
		t.Fatal("failed cutover discarded recoverable migrated credentials")
	}
	if _, err := readCredentialRecord(s.configPath + ".credentials.json"); err != nil {
		t.Fatal("failed migration removed legacy credential source")
	}
	if err := os.Remove(s.configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, s.configPath); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	profiles, err := restarted.RemoteProfiles()
	if err != nil || len(profiles) != 1 || restarted.Config().RemoteProfileID != "" {
		t.Fatal("restart repeated a partially completed migration or silently selected it")
	}
}

func TestInterruptedMigrationRestartCannotKeepHiddenLegacyAccountAfterClearOrDelete(t *testing.T) {
	for _, action := range []string{"clear", "delete"} {
		t.Run(action, func(t *testing.T) {
			s := profileService(t)
			c := s.Config()
			c.ProxyURL, c.ExpectedIPs = "https://legacy.example:8443", []string{"203.0.113.7"}
			if err := s.SaveConfig(c); err != nil {
				t.Fatal(err)
			}
			if err := s.SetProxyCredentialsWithRemember("fixture-original", "fixture-password", true); err != nil {
				t.Fatal(err)
			}
			backup := s.configPath + ".fixture-backup"
			if err := os.Rename(s.configPath, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(s.configPath, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.EnsureRemoteProfiles(); err == nil {
				t.Fatal("fixture did not interrupt the migration's config reference write")
			}
			if err := os.Remove(s.configPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, s.configPath); err != nil {
				t.Fatal(err)
			}
			restarted, err := New(s.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if restarted.Config().ProxyURL != "https://legacy.example:8443" || restarted.proxyUsername != "fixture-original" {
				t.Fatal("startup discarded unreconciled sources before safe migration completion")
			}
			if err := restarted.Arm(context.Background()); !errors.Is(err, errProfileSelectionRequired) {
				t.Fatal("startup allowed implicit legacy activation before migration reconciliation")
			}
			if err := restarted.Check(context.Background()); !errors.Is(err, errProfileSelectionRequired) {
				t.Fatal("startup allowed a legacy check before migration reconciliation")
			}
			if _, err := restarted.ProbeCandidate(context.Background()); !errors.Is(err, errProfileSelectionRequired) {
				t.Fatal("startup allowed a legacy candidate probe before migration reconciliation")
			}
			if err := restarted.EnsureRemoteProfiles(); err != nil {
				t.Fatal(err)
			}
			profiles, err := restarted.RemoteProfiles()
			if err != nil || len(profiles) != 1 {
				t.Fatalf("interrupted migration lost its recoverable profile: %v", err)
			}
			if restarted.Config().RemoteProfileID != "" {
				t.Fatal("interrupted migration implicitly selected its recoverable profile")
			}
			p := profiles[0]
			if action == "clear" {
				_, err = restarted.SaveRemoteProfile(model.RemoteProfileInput{ID: p.ID, Name: p.Name, ProxyURL: p.ProxyURL, ExpectedIPs: p.ExpectedIPs, CredentialAction: "clear"})
			} else {
				err = restarted.DeleteRemoteProfile(p.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if restarted.Config().ProxyURL != "" || len(restarted.Config().ExpectedIPs) != 0 || restarted.proxyUsername != "" || restarted.proxyPassword != "" || restarted.Status().UpstreamCredentialsSet {
				t.Fatal("cleared/deleted imported profile left a hidden usable legacy route or account")
			}
			if _, err := os.Stat(s.configPath + ".credentials.json"); !os.IsNotExist(err) {
				t.Fatal("completed interrupted migration retained the hidden legacy account file")
			}
			restarted.makeRemoteRoute = func(context.Context, model.Config, string, string) (route, error) {
				t.Fatal("unselected legacy route reached route construction after clear/delete")
				return nil, nil
			}
			if err := restarted.Check(context.Background()); err == nil {
				t.Fatal("unselected cleared/deleted imported profile remained checkable")
			}
			again, err := New(s.configPath)
			if err != nil || again.Config().ProxyURL != "" || again.proxyUsername != "" {
				t.Fatalf("another restart recovered the deleted hidden legacy route/account: %v", err)
			}
		})
	}
}

func TestUnselectedProfileLibraryDoesNotSuspendNonRemoteLegacySource(t *testing.T) {
	s := profileService(t)
	c := s.Config()
	c.Mode, c.ProxyURL = "proxy", "http://127.0.0.1:7890"
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	saveProfile(t, s, "Unselected", "https://proxy.example:8443", "fixture-unused")
	restarted, err := New(s.configPath)
	if err != nil || restarted.profileError != nil || restarted.Config().Mode != "proxy" || restarted.Config().ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("saved remote profiles suspended an unrelated local source: %v", err)
	}
}

func TestExistingUnrelatedProfileLibraryBlocksLegacyWithoutDiscardingItsSources(t *testing.T) {
	s := profileService(t)
	c := s.Config()
	c.ProxyURL, c.ExpectedIPs = "https://legacy.example:8443", []string{"203.0.113.7"}
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProxyCredentialsWithRemember("fixture-original", "fixture-password", true); err != nil {
		t.Fatal(err)
	}
	other := saveProfile(t, s, "Unrelated", "https://other.example:9443", "fixture-other")
	if err := s.EnsureRemoteProfiles(); err == nil {
		t.Fatal("existing library allowed a hidden unmatched legacy route")
	}
	if s.Status().State != "blocked" || s.armedIntent || s.Config().RemoteProfileID != "" {
		t.Fatal("unmatched legacy source was selected or left implicitly runnable")
	}
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("unmatched legacy route could be checked instead of explicitly saved or selected")
	}
	legacy, err := readCredentialRecord(s.configPath + ".credentials.json")
	if err != nil || legacy.Username != "fixture-original" || legacy.Password != "fixture-password" {
		t.Fatal("unmatched source account was deleted without a recoverable profile")
	}
	savedConfig, err := loadConfig(s.configPath)
	if err != nil || savedConfig.ProxyURL != "https://legacy.example:8443" || len(savedConfig.ExpectedIPs) != 1 {
		t.Fatal("unmatched legacy configuration was discarded")
	}
	profiles, err := s.RemoteProfiles()
	if err != nil || len(profiles) != 1 || profiles[0].ID != other.ID {
		t.Fatal("legacy startup overwrote or silently merged the unrelated profile library")
	}
}

type delayedProfileRoute struct {
	entered chan struct{}
	release chan struct{}
}

func (r *delayedProfileRoute) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("fixture only")
}
func (r *delayedProfileRoute) Fingerprint(context.Context) (string, error) {
	return "fixture-path", nil
}
func (r *delayedProfileRoute) Close() error { return nil }
func (r *delayedProfileRoute) Probe(context.Context, string) (string, error) {
	close(r.entered)
	<-r.release // deliberately ignores cancellation, like a slow external call
	return "203.0.113.7", nil
}

func TestSelectingAnotherProfileCancelsStaleValidation(t *testing.T) {
	s := profileService(t)
	a := saveProfile(t, s, "First", "https://proxy.example:8443", "fixture-a")
	b := saveProfile(t, s, "Second", "https://proxy.example:8443", "fixture-b")
	if err := s.SelectRemoteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	r := &delayedProfileRoute{entered: make(chan struct{}), release: make(chan struct{})}
	s.makeRemoteRoute = func(_ context.Context, c model.Config, username, password string) (route, error) {
		if c.RemoteProfileID != a.ID || username != "fixture-a" || password != "fixture-password-fixture-a" {
			t.Error("validation did not capture the first complete selected pair")
		}
		return r, nil
	}
	done := make(chan error, 1)
	go func() { done <- s.Check(context.Background()) }()
	select {
	case <-r.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("validation did not enter fixture probe")
	}
	if err := s.SelectRemoteProfile(b.ID); err != nil {
		t.Fatal(err)
	}
	close(r.release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stale validation published success after selection changed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale validation did not finish")
	}
	if s.Config().RemoteProfileID != b.ID || s.proxyUsername != "fixture-b" || s.activeRoute != nil || s.armedIntent || s.Status().State != "unconfigured" {
		t.Fatal("old validation resurrected a former proxy or overwrote selected state")
	}
}

func TestSelectedProfileSwitchRevokesLateAutomaticRecovery(t *testing.T) {
	requireCredentialPersistence(t)
	s := configured(t)
	a := saveProfile(t, s, "First", "https://proxy.example:8443", "fixture-a")
	b := saveProfile(t, s, "Second", "https://proxy.example:8443", "fixture-b")
	if err := s.SelectRemoteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	optInRecovery(t, s, "proxy-only")
	clock := newRecoveryClock()
	s.recoveryWait = clock.wait
	var fail atomic.Bool
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	initial := &recoveryRoute{fp: "same-endpoint", probe: func(context.Context) (string, error) {
		if fail.Load() {
			return "", context.DeadlineExceeded
		}
		return "203.0.113.7", nil
	}}
	candidate := &recoveryRoute{fp: "same-endpoint", probe: func(context.Context) (string, error) {
		close(entered)
		<-release
		return "203.0.113.7", nil
	}}
	s.makeRemoteRoute = func(_ context.Context, c model.Config, username, password string) (route, error) {
		if c.RemoteProfileID != a.ID || username != "fixture-a" || password != "fixture-password-fixture-a" {
			t.Error("automatic recovery captured a different profile's identity")
		}
		if calls.Add(1) == 1 {
			return initial, nil
		}
		return candidate, nil
	}
	if err := s.Arm(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	s.health(context.Background())
	tick := clock.next(t, 2*time.Second)
	close(tick.release)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("automatic recovery did not enter its candidate probe")
	}
	if err := s.SelectRemoteProfile(b.ID); err != nil {
		t.Fatal(err)
	}
	before := s.Status()
	close(release)
	waitRecoveryWorkerExit(t, s)
	if !reflect.DeepEqual(s.Status(), before) || s.Config().RemoteProfileID != b.ID || s.proxyUsername != "fixture-b" || s.armedIntent || s.activeRoute != nil || candidate.closed.Load() != 1 {
		t.Fatal("late recovery revived the former profile or changed the newly selected state")
	}
}

func TestProfileLibraryRejectsUnsafeFileAndParentPermissions(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("POSIX fixtures; Windows uses existing private DACL helpers")
	}
	s := profileService(t)
	p := saveProfile(t, s, "Saved", "https://proxy.example:8443", "fixture-user")
	if err := s.SelectRemoteProfile(p.ID); err != nil {
		t.Fatal(err)
	}
	path := s.configPath + ".profiles.json"
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoteProfiles(); err == nil {
		t.Fatal("world-readable private profile library accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	backup := path + ".fixture-backup"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoteProfiles(); err == nil {
		t.Fatal("profile library read followed a final symlink")
	}
	if err := writeProfileLibrary(path, profileLibrary{Version: 1, Profiles: []remoteProfileRecord{}}); err == nil {
		t.Fatal("profile write replaced a linked target")
	}
	parentLink := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(filepath.Dir(s.configPath), parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProfileLibrary(filepath.Join(parentLink, filepath.Base(path))); err == nil {
		t.Fatal("profile library read followed a linked parent directory")
	}
}
