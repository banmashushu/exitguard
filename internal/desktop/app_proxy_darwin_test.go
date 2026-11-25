package desktop

import (
	"context"
	"strings"
	"testing"

	legacy "exitguard/internal/ui"
	native "github.com/egoist/mygo/ui"
)

func TestOverviewAppProxyActionsWorkWithGuardStopped(t *testing.T) {
	core := testCore(t)
	posted := make(chan func(), 32)
	const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	var removed bool
	var launched string
	c := NewController(context.Background(), core, func(f func()) { posted <- f }, Operations{
		RemoveClaudeProxy: func(context.Context) (bool, error) {
			removed = true
			return true, nil
		},
		LaunchChromeWithoutProxy: func(_ context.Context, path string) error {
			launched = path
			return nil
		},
	})
	t.Cleanup(c.Close)
	c.Apps = []legacy.DesktopApplication{{Kind: "browser", Name: "Chrome", Path: chrome, BundleID: "com.google.Chrome"}}
	c.BrowserPath = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
	c.MarkDirty()
	tt := native.NewTester(c.View, 1120, 840)
	tt.Scroll(900, 680, 0, 1200)
	if err := tt.Click("移除 Claude Desktop 代理"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	if !removed || !strings.Contains(c.Notice, "重新打开 Claude") {
		t.Fatalf("Claude removal did not complete through the overview: %q", c.Notice)
	}
	tt.Frame()
	tt.Scroll(900, 680, 0, 1200)
	if err := tt.Click("无代理启动 Chrome"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	if launched != chrome || !c.Dirty || c.running() {
		t.Fatalf("Chrome launch used %q or altered the guard or draft", launched)
	}
}
