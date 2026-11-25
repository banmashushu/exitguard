package desktop

import (
	"strings"
	"testing"

	"exitguard/internal/model"
	native "github.com/egoist/mygo/ui"
)

func preProxyDraft() ProfileDraft {
	d := blankProfileDraft()
	d.Name, d.Host = "Fixed exit", "exit.example"
	d.FirstHopSource = "proxy"
	d.PreProxyProtocol, d.PreProxyHost, d.PreProxyPort = "SOCKS5", "127.0.0.1", "1080"
	return d
}

// Dropping the first-hop fields during form conversion would silently change
// the connection route; each protocol must produce its own explicit endpoint.
func TestProfileDraftConvertsIndependentPreProxyFields(t *testing.T) {
	for _, tc := range []struct{ protocol, host, port, want string }{
		{"SOCKS5", "127.0.0.1", "1080", "socks5://127.0.0.1:1080"},
		{"HTTP", "Local.Proxy", "8080", "http://local.proxy:8080"},
		{"HTTPS", " secure.proxy ", "443", "https://secure.proxy:443"},
	} {
		d := preProxyDraft()
		d.Username, d.Password = "final-user", "final-password"
		d.PreProxyProtocol, d.PreProxyHost, d.PreProxyPort = tc.protocol, tc.host, tc.port
		d.PreProxyUsername, d.PreProxyPassword = "first-user", "first-password"
		input, err := d.input()
		if err != nil || input.ProxyURL != "https://exit.example:443" || input.PreProxyURL != tc.want || input.Username != "final-user" || input.Password != "final-password" || input.PreProxyUsername != "first-user" || input.PreProxyPassword != "first-password" || input.ClearPreProxyCredentials {
			t.Fatalf("independent first-hop conversion failed: %v", err)
		}
	}
	d := preProxyDraft()
	d.PreProxyHost = "user:secret@local.proxy"
	if _, err := d.input(); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("first-hop server accepted embedded account or exposed it in an error")
	}
}

func TestDisabledPreProxyClearsItsSavedAccountWithoutSubmittingHiddenFields(t *testing.T) {
	d := preProxyDraft()
	d.FirstHopSource, d.HasPreProxyCredentials = "none", true
	d.PreProxyHost = "invalid hidden host/path"
	d.PreProxyUsername, d.PreProxyPassword = "hidden-user", "hidden-password"
	input, err := d.input()
	if err != nil || input.PreProxyURL != "" || !input.ClearPreProxyCredentials || input.PreProxyUsername != "" || input.PreProxyPassword != "" {
		t.Fatalf("disabled first hop retained endpoint or credentials: %v", err)
	}
}

func TestPreProxyAccountKeepReplaceClearRequiresSameEndpoint(t *testing.T) {
	d := profileDraftFrom(model.RemoteProfile{ID: "saved", Name: "Saved", ProxyURL: "https://exit.example:443", PreProxyURL: "http://local.proxy:8080", HasCredentials: true, HasPreProxyCredentials: true})
	if d.FirstHopSource != "proxy" || d.PreProxyProtocol != "HTTP" || d.PreProxyHost != "local.proxy" || d.PreProxyPort != "8080" || d.Username != "" || d.Password != "" || d.PreProxyUsername != "" || d.PreProxyPassword != "" {
		t.Fatal("saved first-hop endpoint did not load independently without secret refill")
	}
	if input, err := d.input(); err != nil || input.ClearPreProxyCredentials || input.PreProxyUsername != "" || input.PreProxyPassword != "" {
		t.Fatalf("blank same-endpoint fields did not keep the first-hop account: %v", err)
	}
	d.PreProxyHost = "other.proxy"
	if _, err := d.input(); err == nil {
		t.Fatal("changed first hop silently kept its saved account")
	}
	d.PreProxyUsername = "new-user"
	if _, err := d.input(); err == nil {
		t.Fatal("partial first-hop account accepted")
	}
	d.PreProxyPassword = "new-password"
	if input, err := d.input(); err != nil || input.ClearPreProxyCredentials || input.CredentialAction != "keep" {
		t.Fatalf("replacing first-hop account changed the final account: %v", err)
	}
	d.ClearPreProxyCredentials = true
	if _, err := d.input(); err == nil {
		t.Fatal("first-hop replacement and clear accepted together")
	}
	d.PreProxyUsername, d.PreProxyPassword = "", ""
	if input, err := d.input(); err != nil || !input.ClearPreProxyCredentials || input.CredentialAction != "keep" {
		t.Fatalf("explicit first-hop clear failed: %v", err)
	}
}

func TestOldProfilesDefaultToNoPreProxy(t *testing.T) {
	d := profileDraftFrom(model.RemoteProfile{Name: "Old", ProxyURL: "https://exit.example:443"})
	input, err := d.input()
	if err != nil || d.FirstHopSource != "none" || input.PreProxyURL != "" || !input.ClearPreProxyCredentials {
		t.Fatalf("old profile unexpectedly enabled a first hop: %v", err)
	}
}

func TestAdvancedDraftPreservesEnabledPreProxy(t *testing.T) {
	config := model.Config{Mode: "remote", ProxyURL: "https://exit.example:443", PreProxyURL: "socks5://127.0.0.1:1080", ProxyPort: 18980}
	d := draftFrom(config)
	d.DNSBootstrapIP = "8.8.8.8"
	saved, err := d.config()
	if err != nil || saved.PreProxyURL != "socks5://127.0.0.1:1080" || saved.DNSBootstrapIP != "8.8.8.8" {
		t.Fatalf("advanced settings discarded the first-hop route: %v", err)
	}
}

func TestPreProxySaveClearsSubmittedAccountsAndPreservesNewerInputs(t *testing.T) {
	s := &delayedProfileSave{Core: testCore(t), entered: make(chan struct{}), release: make(chan struct{})}
	c, posted := controllerForTest(t, s)
	c.ProfileDraft = preProxyDraft()
	c.ProfileDraft.Username, c.ProfileDraft.Password = "final-user", "final-password"
	c.ProfileDraft.PreProxyUsername, c.ProfileDraft.PreProxyPassword = "first-user", "first-password"
	c.MarkProfileDirty()
	c.SaveProfile()
	if c.ProfileDraft.Username != "" || c.ProfileDraft.Password != "" || c.ProfileDraft.PreProxyUsername != "" || c.ProfileDraft.PreProxyPassword != "" {
		t.Fatal("submitted accounts remained in form")
	}
	<-s.entered
	c.ProfileDraft.PreProxyHost = "later.proxy"
	c.ProfileDraft.Username, c.ProfileDraft.Password = "later-final", "later-final-password"
	c.ProfileDraft.PreProxyUsername, c.ProfileDraft.PreProxyPassword = "later-first", "later-first-password"
	c.MarkProfileDirty()
	close(s.release)
	finish(t, c, posted)
	if !c.ProfileDirty || c.ProfileDraft.ID == "" || !c.ProfileDraft.HasCredentials || !c.ProfileDraft.HasPreProxyCredentials || c.ProfileDraft.PreProxyHost != "later.proxy" || c.ProfileDraft.Password != "later-final-password" || c.ProfileDraft.PreProxyPassword != "later-first-password" {
		t.Fatal("save settlement discarded newer account edits or saved chain metadata")
	}
	if len(c.Profiles) != 1 || c.Profiles[0].PreProxyURL != "socks5://127.0.0.1:1080" || c.Config.PreProxyURL != "" || c.Config.RemoteProfileID != "" {
		t.Fatal("save did not persist immutable first-hop endpoint independently from activation")
	}
}

func TestNativePreProxyToggleEditsDraftWithoutActivationAndMasksPassword(t *testing.T) {
	c, _ := controllerForTest(t, testCore(t))
	c.Page = "代理设置"
	tt := native.NewTester(c.View, 1120, 1200)
	if err := tt.Click("第一跳来源"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("已有代理地址"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.FirstHopSource != "proxy" || !c.ProfileDirty || c.Config.PreProxyURL != "" || c.Busy {
		t.Fatal("first-hop toggle changed active configuration or failed to mark local edits")
	}
	if err := tt.Click("前置代理协议"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("SOCKS5"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.PreProxyProtocol != "SOCKS5" {
		t.Fatal("first-hop protocol control did not update its own endpoint")
	}
	if err := tt.Click("前置代理密码"); err != nil {
		t.Fatal(err)
	}
	tt.Type("never-show-first-hop-password")
	tt.Key(native.Cmd, native.KeyA)
	tt.Command("copy")
	if c.ProfileDraft.PreProxyPassword != "never-show-first-hop-password" || tt.Clipboard() != "" || strings.Contains(strings.Join(tt.Texts(), " "), "never-show-first-hop-password") {
		t.Fatal("first-hop password exposed by native form")
	}
}

func TestNativeExpandedPreProxyEditorCanSaveAfterScrolling(t *testing.T) {
	for _, size := range []struct {
		name          string
		width, height int
	}{{"default", 1120, 840}, {"narrow", 840, 720}} {
		t.Run(size.name, func(t *testing.T) {
			c, posted := controllerForTest(t, testCore(t))
			c.Page, c.ProfileDraft = "代理设置", preProxyDraft()
			c.MarkProfileDirty()
			tt := native.NewTester(c.View, size.width, size.height)
			tt.Scroll(float32(size.width-100), float32(size.height-150), 0, 900)
			if err := tt.Click("保存代理"); err != nil {
				t.Fatal(err)
			}
			finish(t, c, posted)
			if len(c.Profiles) != 1 || c.Profiles[0].PreProxyURL != "socks5://127.0.0.1:1080" || c.ProfileDirty || c.Config.RemoteProfileID != "" {
				t.Fatal("expanded editor did not save the first hop independently after scrolling")
			}
		})
	}
}

func TestSavedPreProxyCanBeDisabledWithoutRetainingItsAccount(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	c.ProfileDraft = preProxyDraft()
	c.ProfileDraft.PreProxyUsername, c.ProfileDraft.PreProxyPassword = "first-user", "first-password"
	c.MarkProfileDirty()
	c.SaveProfile()
	finish(t, c, posted)
	id := c.ProfileDraft.ID
	if !c.ProfileDraft.HasPreProxyCredentials {
		t.Fatal("fixture did not save its first-hop account")
	}
	c.UseProfile(id)
	finish(t, c, posted)
	c.ProfileDraft.FirstHopSource = "none"
	c.MarkProfileDirty()
	c.UseProfile(id)
	if c.Busy || c.Config.PreProxyURL != "socks5://127.0.0.1:1080" {
		t.Fatal("editing a first hop changed the active route before saving")
	}
	c.Check()
	if c.Busy {
		t.Fatal("dirty first-hop changes admitted a network check")
	}
	c.SaveProfile()
	finish(t, c, posted)
	if c.ProfileDraft.FirstHopSource != "none" || c.ProfileDraft.HasPreProxyCredentials || len(c.Profiles) != 1 || c.Profiles[0].PreProxyURL != "" || c.Profiles[0].HasPreProxyCredentials || c.Config.PreProxyURL != "" {
		t.Fatal("saving disabled first hop retained its endpoint or account")
	}
}
