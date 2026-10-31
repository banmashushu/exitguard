package desktop

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"exitguard/internal/model"
	native "github.com/egoist/mygo/ui"
)

func fillProfile(c *Controller, name, host, username, password string) {
	c.ProfileDraft.Name, c.ProfileDraft.Protocol = name, "HTTPS"
	c.ProfileDraft.Host, c.ProfileDraft.Port = host, "443"
	c.ProfileDraft.Username, c.ProfileDraft.Password = username, password
	c.MarkProfileDirty()
}

func TestIndependentProfilesSaveThenExplicitlyUseWithoutArming(t *testing.T) {
	s := testCore(t)
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Tokyo", "tokyo.example", "account-a", "password-a")
	c.SaveProfile()
	if c.ProfileDraft.Username != "" || c.ProfileDraft.Password != "" {
		t.Fatal("submitted credentials remain in UI")
	}
	finish(t, c, posted)
	a := c.ProfileDraft.ID
	if a == "" || !c.ProfileDraft.HasCredentials || c.Config.RemoteProfileID != "" {
		t.Fatal("new profile was not saved independently")
	}
	c.NewProfile()
	fillProfile(c, "London", "london.example", "account-b", "password-b")
	c.SaveProfile()
	finish(t, c, posted)
	b := c.ProfileDraft.ID
	if a == b || len(c.Profiles) != 2 {
		t.Fatal("second save replaced first profile")
	}
	c.EditProfile(a)
	if c.ProfileDraft.Name != "Tokyo" || c.ProfileDraft.Host != "tokyo.example" || c.ProfileDraft.Username != "" || c.ProfileDraft.Password != "" {
		t.Fatal("editing did not restore only nonsecret profile fields")
	}
	c.UseProfile(b)
	finish(t, c, posted)
	if c.Config.RemoteProfileID != b || c.Config.ProxyURL != "https://london.example:443" || c.Status.State == "armed" || c.Status.State == "proxy_active" || c.ProfileDraft.ID != a {
		t.Fatal("explicit use did not select the requested profile while keeping the editor independent and closed")
	}
}

func TestProfileRefreshAndSelectionGuardPreserveUnsavedDraft(t *testing.T) {
	s := testCore(t)
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Saved", "saved.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	id := c.ProfileDraft.ID
	c.NewProfile()
	fillProfile(c, "Draft", "draft.example", "pending-user", "pending-password")
	c.Refresh()
	if !c.ProfileDirty || c.ProfileDraft.Host != "draft.example" || c.ProfileDraft.Password != "pending-password" {
		t.Fatal("refresh discarded the draft")
	}
	c.EditProfile(id)
	if c.PendingProfileAction != "edit" || c.ProfileDraft.Name != "Draft" {
		t.Fatal("changing selection discarded a dirty draft without confirmation")
	}
	c.CancelProfileChange()
	if c.ProfileDraft.Name != "Draft" || c.ProfileDraft.Password != "pending-password" {
		t.Fatal("cancel discarded draft")
	}
	c.EditProfile(id)
	c.DiscardProfileChanges()
	if c.ProfileDirty || c.ProfileDraft.ID != id || c.ProfileDraft.Password != "" {
		t.Fatal("confirmed discard did not load the requested profile and clear secret input")
	}
}

func TestProfileDeleteRequiresConfirmAndCanCancel(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	fillProfile(c, "Delete", "delete.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	id := c.ProfileDraft.ID
	c.RequestDeleteProfile(id)
	if c.Busy || len(c.Profiles) != 1 || c.DeleteProfileID != id {
		t.Fatal("request deleted before confirmation")
	}
	c.CancelDeleteProfile()
	if c.DeleteProfileID != "" || len(c.Profiles) != 1 {
		t.Fatal("cancel changed saved profiles")
	}
	c.RequestDeleteProfile(id)
	c.ConfirmDeleteProfile()
	finish(t, c, posted)
	if len(c.Profiles) != 0 || c.ProfileDraft.ID != "" {
		t.Fatal("confirmed delete did not remove selected profile")
	}
}

func TestProfileCredentialRulesRejectPartialOrUnboundSavedAccount(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	fillProfile(c, "Account", "old.example", "user", "password")
	c.SaveProfile()
	finish(t, c, posted)
	c.ProfileDraft.Host = "new.example"
	c.MarkProfileDirty()
	c.SaveProfile()
	if c.Busy || !strings.Contains(c.Notice, "账户") {
		t.Fatal("old endpoint account accepted for a new endpoint")
	}
	c.ProfileDraft.Username = "new-user"
	c.SaveProfile()
	if c.Busy {
		t.Fatal("partial credential pair was accepted")
	}
	c.ProfileDraft.Username = ""
	c.ProfileDraft.ClearCredentials = true
	c.SaveProfile()
	finish(t, c, posted)
	if c.ProfileDraft.HasCredentials || c.ProfileDraft.Host != "new.example" {
		t.Fatal("explicit clear did not save new endpoint without old credentials")
	}
}

type delayedProfileSave struct {
	once sync.Once
	Core
	entered, release chan struct{}
}

func (s *delayedProfileSave) SaveRemoteProfile(input model.RemoteProfileInput) (model.RemoteProfile, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	return s.Core.SaveRemoteProfile(input)
}

func TestProfileSaveCompletionKeepsNewerEditsAndNewRecordIdentity(t *testing.T) {
	s := &delayedProfileSave{Core: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "First", "first.example", "", "")
	c.SaveProfile()
	<-s.entered
	c.ProfileDraft.Name = "Later draft"
	c.MarkProfileDirty()
	close(s.release)
	finish(t, c, posted)
	if !c.ProfileDirty || c.ProfileDraft.Name != "Later draft" || c.ProfileDraft.ID == "" {
		t.Fatal("completion replaced new draft or lost its saved identity")
	}
	if len(c.Profiles) != 1 || c.Profiles[0].Name != "First" {
		t.Fatal("save did not use its immutable input")
	}
}

func TestNativeProfileFormSavesOneSubmissionAndMasksPassword(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	c.Page = "代理设置"
	tt := native.NewTester(c.View, 1120, 1000)
	for _, field := range []struct{ label, value string }{{"代理名称", "Japan"}, {"服务器 / IP", "jp.example"}, {"端口", "443"}, {"代理用户名", "typed-user"}, {"代理密码", "never-show-password"}} {
		if err := tt.Click(field.label); err != nil {
			t.Fatal(err)
		}
		tt.Key(native.Cmd, native.KeyA)
		tt.Type(field.value)
	}
	tt.Key(native.Cmd, native.KeyA)
	tt.Command("copy")
	if tt.Clipboard() != "" || strings.Contains(strings.Join(tt.Texts(), " "), "never-show-password") {
		t.Fatal("password exposed by native form")
	}
	if err := tt.Click("保存代理"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	tt.Frame()
	if len(c.Profiles) != 1 || c.Profiles[0].Name != "Japan" || !c.Profiles[0].HasCredentials || c.ProfileDraft.Password != "" {
		t.Fatal("native one-step save did not persist profile and clear password")
	}
}

func TestNativeProtocolSelectionUpdatesProfileDraft(t *testing.T) {
	c, _ := controllerForTest(t, testCore(t))
	c.Page = "代理设置"
	tt := native.NewTester(c.View, 1120, 1000)
	if err := tt.Click("协议"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("SOCKS5"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.Protocol != "SOCKS5" || !c.ProfileDirty {
		t.Fatal("protocol selection did not update profile draft")
	}
	c.Refresh()
	tt.Frame()
	if c.ProfileDraft.Protocol != "SOCKS5" {
		t.Fatal("refresh discarded protocol selection")
	}
}

func TestProfilePauseSuppressesLateSelectionSuccess(t *testing.T) {
	// The ordinary action slot and epoch path are shared by profile operations.
	c, posted := controllerForTest(t, testCore(t))
	fillProfile(c, "One", "one.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	c.UseProfile(c.ProfileDraft.ID)
	c.Pause()
	finish(t, c, posted)
	if c.Status.State != "stopped" || strings.Contains(c.Notice, "已使用") {
		t.Fatal("late profile completion replaced manual pause")
	}
}

func TestChangingSourceToRemoteCanExplicitlyUseSavedProfile(t *testing.T) {
	s := testCore(t)
	config := s.Config()
	config.Mode = "feilian"
	if err := s.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Remote", "remote.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	c.Draft.Mode = "remote"
	c.MarkDirty()
	c.UseProfile(c.ProfileDraft.ID)
	finish(t, c, posted)
	if c.Config.Mode != "remote" || c.Config.RemoteProfileID == "" || c.Dirty {
		t.Fatal("a source-only remote draft prevented explicit profile use")
	}
}

func TestNativeSavedProfileListScrollsToThirtySecondAndEditsWithoutSwitch(t *testing.T) {
	s := testCore(t)
	for i := 1; i <= 32; i++ {
		_, err := s.SaveRemoteProfile(model.RemoteProfileInput{Name: fmt.Sprintf("Proxy %02d", i), ProxyURL: "https://proxy.example:443", CredentialAction: "keep"})
		if err != nil {
			t.Fatal(err)
		}
	}
	c, _ := controllerForTest(t, s)
	c.Page = "代理设置"
	tt := native.NewTester(c.View, 1120, 840)
	if err := tt.Click("编辑 Proxy 01"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.Name != "Proxy 01" {
		t.Fatal("list click did not update editor")
	}
	tt.Scroll(350, 450, 0, 12000)
	if err := tt.Click("编辑 Proxy 32"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.Name != "Proxy 32" || c.Config.RemoteProfileID != "" {
		t.Fatal("last visible profile did not enter editor independently")
	}
}

func TestNativeOverviewSelectionAndDeleteConfirmation(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	fillProfile(c, "Saved", "saved.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	id := c.ProfileDraft.ID
	tt := native.NewTester(c.View, 1120, 1000)
	if err := tt.Click("选择已保存代理"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("1 · Saved · https://saved.example:443"); err != nil {
		t.Fatal(err)
	}
	if c.OverviewProfileID != id || c.Config.RemoteProfileID != "" {
		t.Fatal("selection did not update model independently from network")
	}
	if err := tt.Click("使用所选代理"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	tt.Frame()
	if c.Config.RemoteProfileID != id {
		t.Fatal("explicit use did not select profile")
	}
	if err := tt.Click("代理设置"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("删除代理"); err != nil {
		t.Fatal(err)
	}
	tt.Scroll(900, 650, 0, 300)
	if err := tt.Click("取消删除"); err != nil {
		t.Fatal(err)
	}
	if len(c.Profiles) != 1 {
		t.Fatal("cancel removed saved profile")
	}
	if err := tt.Click("删除代理"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("确认删除"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	if len(c.Profiles) != 0 || c.Config.RemoteProfileID != "" {
		t.Fatal("confirmed deletion did not remove active profile")
	}
}

func TestPausedSuccessfulProfileSaveSettlesIdentityAndKeepsSavedAccount(t *testing.T) {
	s := &delayedProfileSave{Core: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Delayed", "delayed.example", "saved-user", "saved-password")
	c.SaveProfile()
	<-s.entered
	c.Pause()
	close(s.release)
	finish(t, c, posted)
	if c.ProfileDraft.ID == "" || !c.ProfileDraft.HasCredentials || len(c.Profiles) != 1 {
		t.Fatal("canceled completion lost the persisted record identity or account state")
	}
	id := c.ProfileDraft.ID
	if c.Status.State != "stopped" || !strings.Contains(c.Notice, "已暂停") {
		t.Fatal("settlement replaced pause or reopened forwarding")
	}
	c.ProfileDraft.Name = "Renamed"
	c.MarkProfileDirty()
	c.SaveProfile()
	finish(t, c, posted)
	if len(c.Profiles) != 1 || c.Profiles[0].ID != id || c.Profiles[0].Name != "Renamed" || !c.Profiles[0].HasCredentials {
		t.Fatal("retry created a duplicate record or discarded the saved account")
	}
}

type delayedProfileDelete struct {
	Core
	entered, release chan struct{}
}

func (s *delayedProfileDelete) DeleteRemoteProfile(id string) error {
	close(s.entered)
	<-s.release
	return s.Core.DeleteRemoteProfile(id)
}
func TestPausedSuccessfulDeleteReconcilesEditorWithoutReplacingPause(t *testing.T) {
	s := &delayedProfileDelete{Core: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Delete", "delete.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	c.RequestDeleteProfile(c.ProfileDraft.ID)
	c.ConfirmDeleteProfile()
	<-s.entered
	c.Pause()
	close(s.release)
	finish(t, c, posted)
	if len(c.Profiles) != 0 || c.ProfileDraft.ID != "" || c.DeleteProfileID != "" || c.Status.State != "stopped" || !strings.Contains(c.Notice, "已暂停") {
		t.Fatal("persisted delete left stale editor identity or replaced pause")
	}
}

func TestProfileDeleteCompletionPreservesNewerDraft(t *testing.T) {
	s := &delayedProfileDelete{Core: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Delete", "delete.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	c.RequestDeleteProfile(c.ProfileDraft.ID)
	c.ConfirmDeleteProfile()
	<-s.entered
	fillProfile(c, "New draft", "new.example", "new-user", "new-password")
	close(s.release)
	finish(t, c, posted)
	if c.ProfileDraft.ID != "" || c.ProfileDraft.Name != "New draft" || c.ProfileDraft.Password != "new-password" || !c.ProfileDirty {
		t.Fatal("delete completion discarded newer editor input")
	}
}

func TestRemoteProfileUseDoesNotDiscardAdvancedChanges(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	fillProfile(c, "Saved", "saved.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	c.Draft.ProxyPort = "19001"
	c.MarkDirty()
	c.UseProfile(c.ProfileDraft.ID)
	if c.Busy || c.Config.RemoteProfileID != "" || c.Draft.ProxyPort != "19001" || !c.Dirty {
		t.Fatal("profile use discarded an unrelated advanced change")
	}
}

type delayedProfileSelect struct {
	Core
	entered, release chan struct{}
}

func (s *delayedProfileSelect) SelectRemoteProfile(id string) error {
	close(s.entered)
	<-s.release
	return s.Core.SelectRemoteProfile(id)
}
func TestPausedProfileSelectionSettlesSourceOnlyDraft(t *testing.T) {
	core := testCore(t)
	config := core.Config()
	config.Mode = "feilian"
	if err := core.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	s := &delayedProfileSelect{Core: core, entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "Saved", "saved.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	id := c.ProfileDraft.ID
	c.Draft.Mode = "remote"
	c.MarkDirty()
	c.UseProfile(id)
	<-s.entered
	c.Pause()
	close(s.release)
	finish(t, c, posted)
	if c.Dirty || c.Draft.ProxyURL != "https://saved.example:443" || c.OverviewProfileID != id || c.Status.State != "stopped" || !strings.Contains(c.Notice, "已暂停") {
		t.Fatal("paused selection left stale source draft or replaced pause")
	}
}

func TestProfileInitializationReconcilesLegacyDraftAfterInterruptedMigration(t *testing.T) {
	for _, tc := range []struct {
		name           string
		dirty, refresh bool
	}{{"clean", false, false}, {"dirty DNS", true, false}, {"dirty DNS after status refresh", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dirty := tc.dirty
			s := testCore(t)
			config := s.Config()
			config.ProxyURL = "https://legacy.example:443"
			config.ExpectedIPs = []string{"203.0.113.77"}
			if err := s.SaveConfig(config); err != nil {
				t.Fatal(err)
			}
			if _, err := s.SaveRemoteProfile(model.RemoteProfileInput{Name: "Imported", ProxyURL: config.ProxyURL, ExpectedIPs: config.ExpectedIPs, CredentialAction: "keep"}); err != nil {
				t.Fatal(err)
			}
			posted := make(chan func(), 32)
			c := newController(context.Background(), s, func(f func()) { posted <- f }, Operations{})
			t.Cleanup(c.Close)
			if dirty {
				c.Draft.DNSBootstrapIP = "8.8.8.8"
				c.MarkDirty()
			}
			if err := s.EnsureRemoteProfiles(); err != nil {
				t.Fatal(err)
			}
			profiles, err := s.RemoteProfiles()
			if err != nil {
				t.Fatal(err)
			}
			if tc.refresh {
				c.Refresh()
			}
			c.completeProfileInitialization(profiles)
			if c.Config.ProxyURL != "" || len(c.Config.ExpectedIPs) != 0 {
				t.Fatal("fixture did not settle interrupted migration to unselected")
			}
			if dirty {
				if !c.Dirty || c.Draft.DNSBootstrapIP != "8.8.8.8" {
					t.Fatal("initialization overwrote real advanced changes")
				}
			}
			if c.Draft.ProxyURL != "" || c.Draft.ExpectedIPs != "" {
				t.Fatal("startup draft retained untouched detached legacy route")
			}
			c.Save()
			finish(t, c, posted)
			if c.Config.ProxyURL != "" || len(c.Config.ExpectedIPs) != 0 {
				t.Fatal("advanced save resurrected detached legacy route")
			}
			if dirty && c.Config.DNSBootstrapIP != "8.8.8.8" {
				t.Fatal("advanced save lost the user-modified DNS setting")
			}
		})
	}
}

func TestNativeOverviewChoiceCannotChangeDuringPendingUse(t *testing.T) {
	s := &delayedProfileSelect{Core: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	fillProfile(c, "A", "a.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	a := c.ProfileDraft.ID
	c.NewProfile()
	fillProfile(c, "B", "b.example", "", "")
	c.SaveProfile()
	finish(t, c, posted)
	b := c.ProfileDraft.ID
	c.OverviewProfileID = a
	c.UseProfile(b)
	<-s.entered
	tt := native.NewTester(c.View, 1120, 1000)
	if err := tt.Click("选择已保存代理"); err != nil {
		t.Fatal(err)
	}
	if tt.HasText("2 · B · https://b.example:443") {
		t.Fatal("busy overview select opened and allowed a later choice to be overwritten")
	}
	close(s.release)
	finish(t, c, posted)
	if c.OverviewProfileID != b {
		t.Fatal("completed use did not settle selected identity")
	}
}
