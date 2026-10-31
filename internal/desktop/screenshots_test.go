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
	// Synthetic examples only; submitted account inputs are cleared before any
	// image is rendered, and no account values are ever used as display labels.
	fillProfile(c, "东京工作代理", "tokyo.example", "review-account", "review-password")
	c.ProfileDraft.ExpectedIPs = "203.0.113.21"
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
}
