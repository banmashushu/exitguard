package desktop

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	native "github.com/egoist/mygo/ui"
)

// Explicit review snapshots contain only a fresh, temporary configuration.
// They use MyGo's in-memory renderer and never create a desktop window.
func TestNativeReviewScreenshots(t *testing.T) {
	dir := os.Getenv("EXITGUARD_UI_SCREENSHOTS")
	if dir == "" {
		t.Skip("set EXITGUARD_UI_SCREENSHOTS to export headless review images")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, posted := controllerForTest(t, testCore(t))
	tt := native.NewTester(c.View, 1120, 840)
	save := func(name string) {
		f, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if err = png.Encode(f, tt.Image()); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	save("overview")
	if err := tt.Click("代理设置"); err != nil {
		t.Fatal(err)
	}
	save("settings")
	c.ProfileDraft = preProxyDraft()
	c.ProfileDraft.Name = "固定出口与前置代理"
	c.MarkProfileDirty()
	tt.Frame()
	save("preproxy-expanded")
	tt.Scroll(900, 650, 0, 360)
	save("preproxy-expanded-bottom")
	tt.SetSize(840, 720)
	tt.Scroll(740, 550, 0, -2000)
	save("preproxy-narrow")
	tt.Scroll(740, 550, 0, 650)
	save("preproxy-narrow-bottom")
	tt.SetSize(1120, 840)
	tt.Scroll(900, 650, 0, -2000)
	c.ProfileDraft = blankProfileDraft()
	c.ProfileDirty = false
	// Synthetic examples only; submitted account inputs are cleared before any
	// image is rendered, and no account values are ever used as display labels.
	fillProfile(c, "东京工作代理", "tokyo.example", "review-account", "review-password")
	c.ProfileDraft.ExpectedIPs = "203.0.113.21"
	c.ProfileDraft.FirstHopSource = "proxy"
	c.ProfileDraft.PreProxyProtocol, c.ProfileDraft.PreProxyHost, c.ProfileDraft.PreProxyPort = "SOCKS5", "127.0.0.1", "1080"
	c.ProfileDraft.PreProxyUsername, c.ProfileDraft.PreProxyPassword = "review-first-account", "review-first-password"
	c.SaveProfile()
	finish(t, c, posted)
	first := c.ProfileDraft.ID
	c.NewProfile()
	fillProfile(c, "伦敦备用代理", "london.example", "", "")
	c.ProfileDraft.Protocol, c.ProfileDraft.Port = "SOCKS5", "1080"
	c.SaveProfile()
	finish(t, c, posted)
	c.UseProfile(first)
	finish(t, c, posted)
	c.Notice = ""
	tt.Frame()
	save("profiles-saved")
	tt.SetSize(840, 720)
	save("profiles-narrow")
	tt.SetSize(1120, 840)
	c.EditProfile(first)
	tt.Frame()
	save("profiles-current-editor")
	c.Advanced = true
	tt.Frame()
	tt.Scroll(800, 650, 0, 720)
	save("settings-bottom")
	c.Page = "出口概览"
	tt.Frame()
	tt.Scroll(800, 300, 0, -2000)
	save("profiles-overview")
	if err := tt.Click("诊断与事件"); err != nil {
		t.Fatal(err)
	}
	save("diagnostics")

	// Managed-subscription screens use only public fixture summaries. No source
	// is downloaded, no managed process starts, and no private URL is rendered.
	subCore := subscriptionFixture(t)
	managed, managedPosted := controllerForTest(t, subCore)
	managed.OpenSubscriptions()
	finish(t, managed, managedPosted)
	managed.ViewSubscription("sub-a")
	tt = native.NewTester(managed.View, 1120, 840)
	save("subscriptions")
	tt.Scroll(950, 650, 0, 650)
	save("subscriptions-nodes")
	tt.SetSize(840, 720)
	tt.Scroll(740, 550, 0, -2000)
	save("subscriptions-narrow")
	tt.Scroll(740, 550, 0, 900)
	save("subscriptions-nodes-narrow")
	managed.SubscriptionDraft.DownloadRoute = "active_exitguard"
	managed.RefreshSubscriptionViaActive("sub-a")
	finish(t, managed, managedPosted)
	tt.SetSize(1120, 840)
	tt.Scroll(950, 650, 0, -2000)
	tt.Frame()
	save("subscriptions-active-route")
	tt.SetSize(840, 720)
	save("subscriptions-active-route-narrow")
	managed.SubscriptionDraft = SubscriptionDraft{ID: "sub-a", Name: "工作订阅", SourceKind: "file"}
	tt.SetSize(1120, 840)
	tt.Scroll(950, 650, 0, -2000)
	tt.Frame()
	save("subscriptions-file")
	tt.SetSize(840, 720)
	save("subscriptions-file-narrow")
	managed.Page = "代理设置"
	managed.ProfileDraft = preProxyDraft()
	managed.ProfileDraft.Name = "固定出口与内置订阅节点"
	managed.ProfileDraft.FirstHopSource = "subscription"
	managed.ChooseManagedSubscription("sub-a")
	managed.ChooseManagedNode("node-a")
	tt.SetSize(1120, 840)
	tt.Scroll(950, 650, 0, -2000)
	tt.Frame()
	save("managed-profile")
	tt.Scroll(950, 650, 0, 650)
	save("managed-profile-bottom")
	tt.SetSize(840, 720)
	tt.Scroll(740, 550, 0, -2000)
	save("managed-profile-narrow")
	tt.Scroll(740, 550, 0, 900)
	save("managed-profile-narrow-bottom")
}
