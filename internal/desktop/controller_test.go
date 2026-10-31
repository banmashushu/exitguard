package desktop

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exitguard/internal/guard"
	"exitguard/internal/model"
	legacy "exitguard/internal/ui"
	native "github.com/egoist/mygo/ui"
)

func testCore(t *testing.T) *guard.Service {
	t.Helper()
	s, err := guard.New(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func controllerForTest(t *testing.T, core Core) (*Controller, chan func()) {
	t.Helper()
	if err := core.EnsureRemoteProfiles(); err != nil {
		t.Fatal(err)
	}
	posted := make(chan func(), 32)
	c := NewController(context.Background(), core, func(f func()) { posted <- f }, Operations{})
	t.Cleanup(c.Close)
	return c, posted
}

func finish(t *testing.T, c *Controller, posted <-chan func()) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for c.Busy {
		select {
		case f := <-posted:
			f()
		case <-deadline:
			t.Fatal("action did not finish")
		}
	}
}

func TestStatusRefreshPreservesUserDraftAndChoice(t *testing.T) {
	s := testCore(t)
	c, _ := controllerForTest(t, s)
	c.Draft.ProxyURL = "https://unsaved.example:443"
	c.MarkDirty()
	c.Username, c.Password, c.Remember = "new-user", "new-password", true
	c.BrowserPath, c.ClaudePath = "/explicit/browser", "/explicit/Claude"
	s.Disarm()
	c.Refresh()
	if c.Draft.ProxyURL != "https://unsaved.example:443" || !c.Dirty || c.Username != "new-user" || c.Password != "new-password" || !c.Remember || c.BrowserPath != "/explicit/browser" || c.ClaudePath != "/explicit/Claude" {
		t.Fatal("status polling replaced user input or selection")
	}
	if c.Status.State != "stopped" {
		t.Fatal("status did not refresh")
	}
}

type delayedArm struct {
	*guard.Service
	entered, release chan struct{}
}

func (s *delayedArm) Arm(ctx context.Context) error {
	close(s.entered)
	<-s.release
	return s.Service.Arm(ctx)
}

func TestPauseBypassesBusyAndQueuedArmCannotRevive(t *testing.T) {
	s := &delayedArm{Service: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	c.Arm()
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("arm never started")
	}
	if !c.Busy {
		t.Fatal("arm did not occupy action slot")
	}
	c.Pause()
	if s.Status().State != "stopped" {
		t.Fatal("pause queued behind validation")
	}
	close(s.release)
	finish(t, c, posted)
	if c.Status.State != "stopped" || s.Status().State != "stopped" || strings.Contains(c.Notice, "已启动") {
		t.Fatal("late arm replaced pause")
	}
}

type delayedSave struct {
	*guard.Service
	entered, release chan struct{}
}

func (s *delayedSave) SaveConfig(config model.Config) error {
	close(s.entered)
	<-s.release
	return s.Service.SaveConfig(config)
}

func TestSaveCompletionDoesNotReplaceNewerEdits(t *testing.T) {
	s := &delayedSave{Service: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	c.Draft.ProxyURL = "https://saved.example:443"
	c.MarkDirty()
	c.Save()
	<-s.entered
	c.Draft.ProxyURL = "https://later.example:443"
	c.MarkDirty()
	close(s.release)
	finish(t, c, posted)
	if c.Draft.ProxyURL != "https://later.example:443" || !c.Dirty {
		t.Fatal("save discarded newer draft")
	}
	if s.Config().ProxyURL != "https://saved.example:443" {
		t.Fatal("wrong submission saved")
	}
}

func TestCredentialSubmissionClearsInputsAndRedactsErrors(t *testing.T) {
	s := testCore(t)
	c, posted := controllerForTest(t, s)
	c.Username, c.Password = "secret-user", "secret-password"
	c.SaveCredentials()
	if c.Username != "" || c.Password != "" {
		t.Fatal("submitted credentials remain in fields")
	}
	finish(t, c, posted)
	if strings.Contains(c.Notice, "secret-") {
		t.Fatal("credential reflected in result")
	}
	if s.Status().UpstreamCredentialsSet {
		t.Fatal("credentials accepted without saved endpoint")
	}
}

func TestDiscoveryKeepsExplicitSelectionAndUsesTypedInventory(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	c.BrowserPath = "/chosen/Chrome"
	c.ops.Discover = func(context.Context) []legacy.DesktopApplication {
		return []legacy.DesktopApplication{{Kind: "browser", Name: "Chrome", Path: "/different/Chrome"}}
	}
	c.Discover()
	finish(t, c, posted)
	if c.BrowserPath != "/chosen/Chrome" || len(c.Apps) != 1 {
		t.Fatal("discovery overwrote selection")
	}
}

func TestNativePasswordStaysMaskedAcrossRefresh(t *testing.T) {
	c, _ := controllerForTest(t, testCore(t))
	c.Page = "代理设置"
	c.ProfileDraft.Password = "never-show-password"
	tt := native.NewTester(c.View, 1100, 1000)
	if err := tt.Click("代理密码"); err != nil {
		t.Fatal(err)
	}
	tt.Key(native.Cmd, native.KeyA)
	tt.Command("copy")
	if tt.Clipboard() != "" || strings.Contains(strings.Join(tt.Texts(), " "), "never-show-password") {
		t.Fatal("password leaked through UI")
	}
	c.Refresh()
	tt.Frame()
	tt.Command("copy")
	if tt.Clipboard() != "" {
		t.Fatal("refresh unmasked password")
	}
}

func TestNativeViewNavigationAndDirtyConfigGate(t *testing.T) {
	c, _ := controllerForTest(t, testCore(t))
	tt := native.NewTester(c.View, 1100, 1000)
	if err := tt.Click("代理设置"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("服务器 / IP"); err != nil {
		t.Fatal(err)
	}
	tt.Type("draft.example")
	if !c.ProfileDirty || !strings.Contains(c.ProfileDraft.Host, "draft.example") {
		t.Fatal("native edit was not retained")
	}
	if err := tt.Click("诊断与事件"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("当前策略") {
		t.Fatal("diagnostic view missing")
	}
}

func TestCanceledControllerDoesNotAcceptNewActions(t *testing.T) {
	c, _ := controllerForTest(t, testCore(t))
	c.Close()
	c.Check()
	if c.Busy {
		t.Fatal("closed controller accepted action")
	}
}

func TestChangingEndpointClearsEnteredOldCredentials(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	c.Username, c.Password, c.Remember = "old-user", "old-password", true
	c.Draft.ProxyURL = "https://new.example:443"
	c.MarkDirty()
	c.Save()
	finish(t, c, posted)
	if c.Username != "" || c.Password != "" || c.Remember {
		t.Fatal("old credentials survived an endpoint change")
	}
}

func TestPausedSaveStillClearsCredentialsWhenEndpointChanged(t *testing.T) {
	s := &delayedSave{Service: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	c.Username, c.Password, c.Remember = "old-user", "old-password", true
	c.Draft.ProxyURL = "https://new.example:443"
	c.MarkDirty()
	c.Save()
	<-s.entered
	c.Pause()
	close(s.release)
	finish(t, c, posted)
	if c.Username != "" || c.Password != "" || c.Remember {
		t.Fatal("canceled save completion retained credentials for the old endpoint")
	}
	if s.Status().State != "stopped" {
		t.Fatal("canceled save replaced manual pause")
	}
}

func TestFirstConfigurationCanBeSavedBeforeScrollingPastCredentials(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	c.Page = "代理设置"
	tt := native.NewTester(c.View, 1120, 840)
	save, ok := tt.Find("保存代理")
	if !ok || save.Y+save.H > 840 {
		t.Fatal("first-time save requires scrolling past the account form")
	}
	if err := tt.Click("服务器 / IP"); err != nil {
		t.Fatal(err)
	}
	tt.Type("configured.example")
	if err := tt.Click("代理名称"); err != nil {
		t.Fatal(err)
	}
	tt.Type("首个代理")
	if err := tt.Click("保存代理"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	if c.ProfileDirty || len(c.Profiles) != 1 || c.Profiles[0].ProxyURL != "https://configured.example:443" || c.Config.RemoteProfileID != "" {
		t.Fatal("first-time server configuration not saved independently")
	}
}

func TestClearCredentialCompletionKeepsNewRememberChoice(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	c.Remember = true
	c.ClearCredentials()
	if c.Remember {
		t.Fatal("clear did not reset the current remember choice")
	}
	c.Remember = true // a new choice for the next submission
	finish(t, c, posted)
	if !c.Remember {
		t.Fatal("late clear completion replaced a newer remember choice")
	}
}

func TestNativeSelectWritesDraftAndClientChoiceAcrossRefresh(t *testing.T) {
	c, _ := controllerForTest(t, testCore(t))
	c.Page = "代理设置"
	c.Apps = []legacy.DesktopApplication{{Kind: "browser", Name: "Test Chrome", Path: "/apps/test-chrome"}, {Kind: "browser", Name: "Test Edge", Path: "/apps/test-edge"}}
	tt := native.NewTester(c.View, 1120, 900)
	if err := tt.Click("出口来源"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("本地固定专用入口"); err != nil {
		t.Fatal(err)
	}
	if c.Draft.Mode != "proxy" || !c.Dirty {
		t.Fatal("native source choice was not committed to the draft")
	}
	c.Refresh()
	tt.Frame()
	if c.Draft.Mode != "proxy" {
		t.Fatal("refresh replaced native source choice")
	}
	if err := tt.Click("出口概览"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("选择浏览器"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("/apps/test-edge"); err != nil {
		t.Fatal(err)
	}
	if c.BrowserPath != "/apps/test-edge" {
		t.Fatal("native browser choice was not committed")
	}
	c.Refresh()
	tt.Frame()
	if c.BrowserPath != "/apps/test-edge" {
		t.Fatal("refresh replaced native browser choice")
	}
}
