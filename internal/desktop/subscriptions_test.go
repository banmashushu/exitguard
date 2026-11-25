package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exitguard/internal/model"
	"exitguard/internal/subscription"
	native "github.com/egoist/mygo/ui"
)

type subscriptionCore struct {
	Core
	summaries                              []model.SubscriptionSummary
	nodes                                  map[string][]model.SubscriptionNode
	input                                  model.SubscriptionInput
	listCalls, imports, refreshes, deletes int
	activeRefreshes                        int
	importError, refreshError              error
	entered, release                       chan struct{}
}

func subscriptionFixture(t *testing.T) *subscriptionCore {
	return &subscriptionCore{Core: testCore(t), summaries: []model.SubscriptionSummary{{ID: "sub-a", Name: "工作订阅", SourceKind: "url", NodeCount: 2, SupportedNodeCount: 1}}, nodes: map[string][]model.SubscriptionNode{"sub-a": {{ID: "node-a", Name: "可用节点", Type: "trojan", Supported: true}, {ID: "node-b", Name: "不支持节点", Type: "unknown", Reason: "暂不支持此协议"}}}}
}
func (s *subscriptionCore) Subscriptions() ([]model.SubscriptionSummary, error) {
	s.listCalls++
	return append([]model.SubscriptionSummary(nil), s.summaries...), nil
}
func (s *subscriptionCore) SubscriptionNodes(id string) ([]model.SubscriptionNode, error) {
	return append([]model.SubscriptionNode(nil), s.nodes[id]...), nil
}
func (s *subscriptionCore) ImportSubscription(ctx context.Context, in model.SubscriptionInput) (model.SubscriptionSummary, error) {
	s.imports++
	s.input = in
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	if s.importError != nil {
		return model.SubscriptionSummary{}, s.importError
	}
	saved := model.SubscriptionSummary{ID: "sub-new", Name: in.Name, SourceKind: "url", DownloadRoute: in.DownloadRoute, NodeCount: 1, SupportedNodeCount: 1}
	if len(in.Content) > 0 {
		saved.SourceKind = "file"
	}
	s.summaries = append(s.summaries, saved)
	s.nodes[saved.ID] = []model.SubscriptionNode{{ID: "node-new", Name: "新节点", Type: "ss", Supported: true}}
	return saved, nil
}
func (s *subscriptionCore) RefreshSubscriptionDirect(ctx context.Context, id string) (model.SubscriptionSummary, error) {
	s.refreshes++
	if s.refreshError != nil {
		return model.SubscriptionSummary{}, s.refreshError
	}
	s.nodes[id] = []model.SubscriptionNode{{ID: "node-replacement", Name: "更新节点", Type: "ss", Supported: true}}
	s.summaries[0].DownloadRoute = subscription.DownloadDirect
	return s.summaries[0], nil
}
func (s *subscriptionCore) RefreshSubscriptionViaActive(ctx context.Context, id string) (model.SubscriptionSummary, error) {
	s.activeRefreshes++
	if s.refreshError != nil {
		return model.SubscriptionSummary{}, s.refreshError
	}
	for i := range s.summaries {
		if s.summaries[i].ID == id {
			s.summaries[i].DownloadRoute = "active_exitguard"
			return s.summaries[i], nil
		}
	}
	return model.SubscriptionSummary{}, errors.New("missing fixture subscription")
}
func (s *subscriptionCore) DeleteSubscription(id string) error {
	s.deletes++
	s.summaries = nil
	delete(s.nodes, id)
	return nil
}

func TestManagedProfileDraftKeepsFixedExitAndMutuallyExclusiveFirstHop(t *testing.T) {
	d := preProxyDraft()
	d.FirstHopSource = "subscription"
	d.ManagedSubscriptionID, d.ManagedNodeID = "sub-a", "node-a"
	d.ExpectedIPs = "203.0.113.5"
	d.Username, d.Password = "fixed-user", "fixed-password"
	d.PreProxyUsername, d.PreProxyPassword = "hidden-user", "hidden-password"
	in, err := d.input()
	if err != nil || in.ProxyURL != "https://exit.example:443" || len(in.ExpectedIPs) != 1 || in.ExpectedIPs[0] != "203.0.113.5" || in.Username != "fixed-user" || in.Password != "fixed-password" || in.ManagedSubscriptionID != "sub-a" || in.ManagedNodeID != "node-a" || in.PreProxyURL != "" || in.PreProxyUsername != "" || in.PreProxyPassword != "" || !in.ClearPreProxyCredentials {
		t.Fatalf("managed first hop changed fixed exit or retained explicit proxy fields: %v", err)
	}
	d.ManagedNodeID = ""
	if _, err = d.input(); err == nil {
		t.Fatal("managed source accepted without an explicit node")
	}
	d.ManagedNodeID = "node-a"
	d.FirstHopSource = "proxy"
	in, err = d.input()
	if err != nil || in.PreProxyURL != "socks5://127.0.0.1:1080" || in.ManagedSubscriptionID != "" || in.ManagedNodeID != "" {
		t.Fatalf("explicit source retained hidden managed IDs: %v", err)
	}
	d.FirstHopSource = "none"
	in, err = d.input()
	if err != nil || in.PreProxyURL != "" || in.ManagedSubscriptionID != "" || in.ManagedNodeID != "" {
		t.Fatalf("disabled source retained a hidden first hop: %v", err)
	}
}

func TestManagedProfileAndAdvancedDraftRoundTripIDsWithoutSelectingNode(t *testing.T) {
	d := profileDraftFrom(model.RemoteProfile{Name: "Fixed", ProxyURL: "https://exit.example:443", ManagedSubscriptionID: "sub-a", ManagedNodeID: "node-a"})
	in, err := d.input()
	if err != nil || d.FirstHopSource != "subscription" || in.ManagedSubscriptionID != "sub-a" || in.ManagedNodeID != "node-a" {
		t.Fatalf("saved profile dropped managed source: %v", err)
	}
	config := model.Config{Mode: "remote", ProxyURL: "https://exit.example:443", ProxyPort: 17890, ManagedSubscriptionID: "sub-a", ManagedNodeID: "node-a"}
	advanced := draftFrom(config)
	advanced.DNSBootstrapIP = "8.8.8.8"
	saved, err := advanced.config()
	if err != nil || saved.ManagedSubscriptionID != "sub-a" || saved.ManagedNodeID != "node-a" {
		t.Fatalf("advanced edit discarded managed route: %v", err)
	}
}

func TestSubscriptionImportClearsPrivateSourcesKeepsNewerEditsAndDoesNotActivate(t *testing.T) {
	s := subscriptionFixture(t)
	s.entered, s.release = make(chan struct{}), make(chan struct{})
	c, posted := controllerForTest(t, s)
	c.SubscriptionDraft = SubscriptionDraft{Name: "First", SourceKind: "url", URL: "https://private.example/sub?token=never-show", DownloadRoute: "active_exitguard"}
	c.MarkSubscriptionDirty()
	c.ImportSubscription()
	if c.SubscriptionDraft.URL != "" || c.SubscriptionDraft.FilePath != "" {
		t.Fatal("private submitted source remained in form")
	}
	<-s.entered
	c.SubscriptionDraft.Name, c.SubscriptionDraft.URL = "Later", "https://later.example/private"
	c.SubscriptionDraft.DownloadRoute = "direct"
	c.MarkSubscriptionDirty()
	c.ImportSubscription()
	close(s.release)
	finish(t, c, posted)
	if s.imports != 1 || s.input.URL != "https://private.example/sub?token=never-show" || s.input.DownloadRoute != "active_exitguard" || len(c.Subscriptions) != 2 || c.SubscriptionDraft.Name != "Later" || c.SubscriptionDraft.URL != "https://later.example/private" || c.SubscriptionDraft.DownloadRoute != "direct" || c.ProfileDraft.ManagedNodeID != "" || c.Config.ManagedNodeID != "" {
		t.Fatal("import reused mutable source, overwrote later edits, or selected a node")
	}
	if strings.Contains(c.Notice, "never-show") {
		t.Fatal("import notice leaked source")
	}
}

func TestSubscriptionFileImportReadsOnlyExplicitBoundedRegularFile(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	path := filepath.Join(t.TempDir(), "nodes.yaml")
	content := []byte("proxies: []\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	c.SubscriptionDraft = SubscriptionDraft{Name: "Local", SourceKind: "file", FilePath: path, URL: "hidden URL", DownloadRoute: "active_exitguard"}
	c.ImportSubscription()
	finish(t, c, posted)
	if string(s.input.Content) != string(content) || s.input.URL != "" || s.input.DownloadRoute != "direct" || c.SubscriptionDraft.FilePath != "" {
		t.Fatal("file import did not deliver only explicitly read content")
	}
	if err := os.WriteFile(path, make([]byte, (5<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	c.SubscriptionDraft = SubscriptionDraft{Name: "Oversized", SourceKind: "file", FilePath: path}
	c.ImportSubscription()
	finish(t, c, posted)
	if s.imports != 1 || strings.Contains(c.Notice, path) {
		t.Fatal("oversized source reached parser or path leaked")
	}
	c.SubscriptionDraft = SubscriptionDraft{Name: "Directory", SourceKind: "file", FilePath: filepath.Dir(path)}
	c.ImportSubscription()
	finish(t, c, posted)
	if s.imports != 1 {
		t.Fatal("directory reached subscription parser")
	}
}

func TestSubscriptionCatalogDoesNotPollAndFailedRefreshKeepsSnapshot(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	c.LoadSubscriptions()
	finish(t, c, posted)
	before := s.listCalls
	c.Refresh()
	c.Refresh()
	if s.listCalls != before {
		t.Fatal("ordinary status polling reloaded subscription catalog")
	}
	s.refreshError = errors.New("https://private.example/secret-source")
	c.RefreshSubscription("sub-a")
	finish(t, c, posted)
	if len(c.Subscriptions) != 1 || c.SubscriptionNodes["sub-a"][0].ID != "node-a" || strings.Contains(c.Notice, "private.example") {
		t.Fatal("failed refresh replaced snapshot or leaked source")
	}
	c.ProfileDraft = profileDraftFrom(model.RemoteProfile{Name: "Fixed", ProxyURL: "https://exit.example:443", ManagedSubscriptionID: "sub-a", ManagedNodeID: "node-a"})
	s.refreshError = nil
	c.RefreshSubscription("sub-a")
	finish(t, c, posted)
	if c.ProfileDraft.ManagedNodeID != "node-a" || c.managedNodeAvailable("sub-a", "node-a") {
		t.Fatal("successful update silently selected a replacement node")
	}
	c.SaveProfile()
	if c.Busy || !strings.Contains(c.Notice, "节点") {
		t.Fatal("removed node was accepted without explicit reselection")
	}
}

func TestManagedSubscriptionChoiceClearsNodeAndNeverChoosesUnsupportedNode(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	c.LoadSubscriptions()
	finish(t, c, posted)
	c.ProfileDraft = preProxyDraft()
	c.ProfileDraft.FirstHopSource = "subscription"
	c.ProfileDraft.ManagedNodeID = "stale"
	c.ChooseManagedSubscription("sub-a")
	if c.ProfileDraft.ManagedNodeID != "" || !c.ProfileDirty || c.Config.ManagedSubscriptionID != "" {
		t.Fatal("subscription choice retained a stale node or activated configuration")
	}
	c.ChooseManagedNode("node-b")
	if c.ProfileDraft.ManagedNodeID != "" {
		t.Fatal("unsupported node was selected")
	}
	c.ChooseManagedNode("node-a")
	if c.ProfileDraft.ManagedNodeID != "node-a" {
		t.Fatal("explicit supported-node choice was discarded")
	}
}

func TestNativeSubscriptionURLIsPrivateAndNavigationDoesNotSelectNode(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	tt := native.NewTester(c.View, 1120, 840)
	if err := tt.Click("订阅管理"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	tt.Frame()
	if err := tt.Click("订阅名称"); err != nil {
		t.Fatal(err)
	}
	tt.Type("Native import")
	if err := tt.Click("私密订阅链接（HTTPS）"); err != nil {
		t.Fatal(err)
	}
	tt.Type("https://private.example/token-never-show")
	tt.Key(native.Cmd, native.KeyA)
	tt.Command("copy")
	if c.SubscriptionDraft.URL != "https://private.example/token-never-show" || tt.Clipboard() != "" || strings.Contains(strings.Join(tt.Texts(), " "), "token-never-show") || c.ProfileDraft.ManagedNodeID != "" {
		t.Fatal("subscription URL exposed or navigation selected a route")
	}
	if err := tt.Click("导入订阅"); err != nil {
		t.Fatal(err)
	}
	if c.SubscriptionDraft.URL != "" {
		t.Fatal("native submit retained private URL")
	}
	finish(t, c, posted)
	if len(c.Subscriptions) != 2 || s.input.URL != "https://private.example/token-never-show" || c.Config.ManagedNodeID != "" {
		t.Fatal("native submit failed to import the private source independently")
	}
}

func TestNativeManagedNodeChoiceIsExplicitAndKeepsFixedExitDraft(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	c.Page = "代理设置"
	fillProfile(c, "固定出口", "exit.example", "fixed-user", "fixed-password")
	c.ProfileDraft.ExpectedIPs = "203.0.113.5"
	tt := native.NewTester(c.View, 1120, 1200)
	if err := tt.Click("第一跳来源"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("内置订阅节点"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	tt.Frame()
	if c.ProfileDraft.ManagedNodeID != "" {
		t.Fatal("switching to subscription source automatically chose a node")
	}
	if err := tt.Click("第一跳订阅"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("1 · 工作订阅"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.ManagedNodeID != "" {
		t.Fatal("choosing subscription automatically chose a node")
	}
	if err := tt.Click("第一跳节点"); err != nil {
		t.Fatal(err)
	}
	if tt.HasText("2 · 不支持节点 · unknown") {
		t.Fatal("unsupported node offered as a route")
	}
	if err := tt.Click("1 · 可用节点 · trojan"); err != nil {
		t.Fatal(err)
	}
	if c.ProfileDraft.ManagedNodeID != "node-a" || c.ProfileDraft.Host != "exit.example" || c.ProfileDraft.Password != "fixed-password" || c.ProfileDraft.ExpectedIPs != "203.0.113.5" || c.Config.ManagedNodeID != "" {
		t.Fatal("native selection changed fixed exit or activated route")
	}
}

func TestSubscriptionImportFailureAndCloseClearSourcesWithoutRefill(t *testing.T) {
	s := subscriptionFixture(t)
	s.importError = errors.New("never-show-subscription-token")
	c, posted := controllerForTest(t, s)
	c.LoadSubscriptions()
	finish(t, c, posted)
	c.SubscriptionDraft = SubscriptionDraft{Name: "Failed", SourceKind: "url", URL: "https://private.example/never-show-subscription-token"}
	c.ImportSubscription()
	finish(t, c, posted)
	if len(c.Subscriptions) != 1 || c.SubscriptionDraft.URL != "" || strings.Contains(c.Notice, "never-show-subscription-token") {
		t.Fatal("failed import changed catalog or disclosed source")
	}
	c.SubscriptionDraft.URL, c.SubscriptionDraft.FilePath = "later-private-source", "private-path"
	c.ProfileDraft.PreProxyUsername, c.ProfileDraft.PreProxyPassword = "first-user", "first-password"
	c.Close()
	if c.SubscriptionDraft.URL != "" || c.SubscriptionDraft.FilePath != "" || c.ProfileDraft.PreProxyUsername != "" || c.ProfileDraft.PreProxyPassword != "" {
		t.Fatal("close retained private subscription or first-hop input")
	}
}

func TestNativeSubscriptionDownloadRouteChoiceIsExplicit(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	c.OpenSubscriptions()
	finish(t, c, posted)
	tt := native.NewTester(c.View, 1120, 1000)
	if err := tt.Click("下载路径"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("通过当前出口下载"); err != nil {
		t.Fatal(err)
	}
	if c.SubscriptionDraft.DownloadRoute != "active_exitguard" || c.Busy || s.imports != 0 || s.refreshes != 0 || s.activeRefreshes != 0 || c.Config.ManagedNodeID != "" {
		t.Fatal("choosing download route implicitly started a subscription or connection action")
	}
	if err := tt.Click("导入方式"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("本机订阅文件"); err != nil {
		t.Fatal(err)
	}
	_, routeShown := tt.Find("下载路径")
	if c.SubscriptionDraft.SourceKind != "file" || c.SubscriptionDraft.DownloadRoute != "direct" || routeShown {
		t.Fatal("file import retained the URL download route control or selection")
	}
}

func TestSubscriptionURLImportUsesOnlyExplicitDownloadRoute(t *testing.T) {
	for _, tc := range []struct{ draft, want string }{{"", "direct"}, {"direct", "direct"}, {"active_exitguard", "active_exitguard"}} {
		s := subscriptionFixture(t)
		c, posted := controllerForTest(t, s)
		c.SubscriptionDraft = SubscriptionDraft{Name: "Route fixture", SourceKind: "url", URL: "https://private.example/token", DownloadRoute: tc.draft}
		c.ImportSubscription()
		finish(t, c, posted)
		if s.input.DownloadRoute != tc.want || c.SubscriptionDraft.DownloadRoute != "direct" || c.SubscriptionDraft.URL != "" {
			t.Fatal("URL import changed its explicit route or retained it for a later new import")
		}
	}
}

func TestSubscriptionActiveRefreshHasNoRetypedURLOrDirectFallback(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	c.LoadSubscriptions()
	finish(t, c, posted)
	c.SubscriptionDraft = SubscriptionDraft{Name: "Later draft", SourceKind: "url", URL: "https://later.example/private", DownloadRoute: "direct"}
	s.refreshError = fmt.Errorf("never-show-secret-source: %w", subscription.ErrActiveRouteUnavailable)
	c.RefreshSubscriptionViaActive("sub-a")
	finish(t, c, posted)
	if s.activeRefreshes != 1 || s.refreshes != 0 || s.imports != 0 || c.Subscriptions[0].DownloadRoute != "" || strings.Contains(c.Notice, "never-show-secret-source") || !strings.Contains(c.Notice, "启动") {
		t.Fatal("failed active refresh changed saved route, leaked source, or retried direct")
	}
	s.refreshError = nil
	c.RefreshSubscriptionViaActive("sub-a")
	finish(t, c, posted)
	if s.activeRefreshes != 2 || s.refreshes != 0 || s.imports != 0 || c.Subscriptions[0].DownloadRoute != "active_exitguard" || c.SubscriptionDraft.URL != "https://later.example/private" || c.Config.ManagedNodeID != "" {
		t.Fatal("active refresh required URL reentry, replaced newer draft, or activated a node")
	}
	c.RefreshSubscription("sub-a")
	finish(t, c, posted)
	if s.refreshes != 1 || s.activeRefreshes != 2 || c.Subscriptions[0].DownloadRoute != subscription.DownloadDirect {
		t.Fatal("direct refresh failed to take precedence over the previous route")
	}
}

func TestNativeStoredSubscriptionCanRefreshThroughCurrentExitWithoutURL(t *testing.T) {
	s := subscriptionFixture(t)
	c, posted := controllerForTest(t, s)
	c.OpenSubscriptions()
	finish(t, c, posted)
	tt := native.NewTester(c.View, 1120, 1000)
	tt.Scroll(950, 850, 0, 800)
	if err := tt.Click("通过当前出口更新 · 工作订阅"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	tt.Frame()
	if s.activeRefreshes != 1 || s.refreshes != 0 || s.imports != 0 || !tt.HasText("下载路径：通过当前出口下载") || c.SubscriptionDraft.URL != "" {
		t.Fatal("stored subscription active-refresh button used wrong route or exposed source")
	}
}

func TestSubscriptionUpdateFeedbackStaysVisibleWhenScrolled(t *testing.T) {
	s := subscriptionFixture(t)
	s.summaries[0].DownloadRoute = "active_exitguard"
	s.refreshError = subscription.ErrActiveRouteUnavailable
	c, posted := controllerForTest(t, s)
	c.OpenSubscriptions()
	finish(t, c, posted)
	c.ViewSubscription("sub-a")
	ui := native.NewTester(c.View, 1120, 840)
	ui.Scroll(950, 730, 0, 550)
	if err := ui.Click("通过当前出口更新 · 工作订阅"); err != nil {
		t.Fatal(err)
	}
	if !c.Busy || !ui.HasText("正在更新订阅") {
		t.Fatal("the update button did not show immediate feedback")
	}
	finish(t, c, posted)
	ui.Frame()
	before, ok := ui.Find(c.Notice)
	if !ok || before.Y < 0 || before.Y+before.H > 150 || !strings.Contains(c.Notice, "已验证活动出口") {
		t.Fatalf("the fixed exit failure is out of view after updating: %v", before)
	}
	ui.Scroll(950, 730, 0, -550)
	after, ok := ui.Find(c.Notice)
	if !ok || before != after || s.refreshes != 0 || s.activeRefreshes != 1 {
		t.Fatal("the update result moved with the page or the action changed the stored route")
	}
}

func TestNativeDirectRefreshUsesSavedURLWithoutCurrentExit(t *testing.T) {
	s := subscriptionFixture(t)
	s.summaries[0].DownloadRoute = subscription.DownloadActiveExitGuard
	c, posted := controllerForTest(t, s)
	c.OpenSubscriptions()
	finish(t, c, posted)
	ui := native.NewTester(c.View, 1120, 1000)
	ui.Scroll(950, 850, 0, 540)
	if err := ui.Click("直接更新订阅 · 工作订阅"); err != nil {
		t.Fatal(err)
	}
	finish(t, c, posted)
	ui.Frame()
	if s.refreshes != 1 || s.activeRefreshes != 0 || s.imports != 0 || c.Subscriptions[0].DownloadRoute != subscription.DownloadDirect || c.Config.ManagedNodeID != "" {
		t.Fatal("the direct update depended on the previously chosen download path or activated a node")
	}
}

func TestLocalSubscriptionProfileWorkflowKeepsOriginalFixedExit(t *testing.T) {
	c, posted := controllerForTest(t, testCore(t))
	path := filepath.Join(t.TempDir(), "controlled-nodes.yaml")
	content := []byte("proxies:\n  - {name: First, type: ss, server: node.example, port: 443, cipher: aes-128-gcm, password: controlled-secret}\n  - {name: Unsupported, type: direct}\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	c.SubscriptionDraft = SubscriptionDraft{Name: "Local fixture", SourceKind: "file", FilePath: path}
	c.ImportSubscription()
	finish(t, c, posted)
	if len(c.Subscriptions) != 1 || len(c.SubscriptionNodes[c.Subscriptions[0].ID]) != 2 {
		t.Fatalf("controlled local subscription import did not finish: %s", c.Notice)
	}
	subID := c.Subscriptions[0].ID
	c.ProfileDraft = preProxyDraft()
	c.ProfileDraft.FirstHopSource = "subscription"
	c.ProfileDraft.Username, c.ProfileDraft.Password = "fixed-user", "fixed-password"
	c.ProfileDraft.ExpectedIPs = "203.0.113.5"
	c.ChooseManagedSubscription(subID)
	nodeID := c.SubscriptionNodes[subID][0].ID
	c.ChooseManagedNode(nodeID)
	c.SaveProfile()
	finish(t, c, posted)
	if c.ProfileDirty || len(c.Profiles) != 1 || c.Profiles[0].ManagedSubscriptionID != subID || c.Profiles[0].ManagedNodeID != nodeID || !c.Profiles[0].HasCredentials || c.Profiles[0].ProxyURL != "https://exit.example:443" || c.Config.RemoteProfileID != "" {
		t.Fatalf("managed profile changed fixed proxy or activated without use: %s", c.Notice)
	}
	c.UseProfile(c.ProfileDraft.ID)
	finish(t, c, posted)
	if c.Config.ManagedNodeID != nodeID || c.Config.ProxyURL != "https://exit.example:443" || len(c.Config.ExpectedIPs) != 1 || c.Config.ExpectedIPs[0] != "203.0.113.5" || c.Status.State == "proxy_active" {
		t.Fatalf("explicit profile use substituted fixed exit or started core: %s", c.Notice)
	}
	c.RequestDeleteSubscription(subID)
	c.ConfirmDeleteSubscription()
	finish(t, c, posted)
	if len(c.Subscriptions) != 1 {
		t.Fatal("referenced subscription was deleted")
	}
	c.ProfileDraft.FirstHopSource = "none"
	c.MarkProfileDirty()
	c.SaveProfile()
	finish(t, c, posted)
	c.RequestDeleteSubscription(subID)
	c.ConfirmDeleteSubscription()
	finish(t, c, posted)
	if len(c.Subscriptions) != 0 || c.Config.ManagedNodeID != "" || c.Config.ProxyURL != "https://exit.example:443" || !c.ProfileDraft.HasCredentials {
		t.Fatalf("detaching first hop changed final account/endpoint or did not allow deletion: %s", c.Notice)
	}
}

func TestSubscriptionUIKeepsSafeEmptyAndDeniedCategories(t *testing.T) {
	for _, test := range []struct {
		failure error
		word    string
	}{{subscription.ErrEmptyResponse, "空"}, {subscription.ErrClientDenied, "客户端"}} {
		s := subscriptionFixture(t)
		s.importError = fmt.Errorf("private-server-marker: %w", test.failure)
		c, posted := controllerForTest(t, s)
		c.SubscriptionDraft = SubscriptionDraft{Name: "Fictitious", SourceKind: "url", URL: "https://private.example/token-hidden"}
		c.ImportSubscription()
		finish(t, c, posted)
		if !strings.Contains(c.Notice, test.word) || strings.Contains(c.Notice, "private-server-marker") || c.SubscriptionDraft.URL != "" {
			t.Fatal("native import erased safe failure category or leaked private input")
		}
		s.refreshError = s.importError
		c.LoadSubscriptions()
		finish(t, c, posted)
		c.RefreshSubscription("sub-a")
		finish(t, c, posted)
		if !strings.Contains(c.Notice, test.word) || len(c.Subscriptions) != 1 || s.nodes["sub-a"][0].ID != "node-a" {
			t.Fatal("native refresh lost safe failure category or old snapshot")
		}
	}
}
