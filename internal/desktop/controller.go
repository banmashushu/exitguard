// Package desktop owns ExitGuard's native, in-process desktop interface.
package desktop

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"exitguard/internal/model"
	legacy "exitguard/internal/ui"
)

// Core exposes typed operations without an HTTP control server or an IPC bridge.
type Core interface {
	legacy.Service
	SetProxyCredentialsWithRemember(string, string, bool) error
	LaunchNativePreview(context.Context, string, string, uint64, bool) error
	EnsureRemoteProfiles() error
	RemoteProfiles() ([]model.RemoteProfile, error)
	SaveRemoteProfile(model.RemoteProfileInput) (model.RemoteProfile, error)
	SelectRemoteProfile(string) error
	DeleteRemoteProfile(string) error
}

type Operations struct {
	Discover func(context.Context) []legacy.DesktopApplication
	Launch   func(legacy.Service, legacy.LaunchRequest) error
}

// Draft is independent of status snapshots; polling never fills these fields.
type Draft struct {
	Mode, EnforcementMode, ProxyURL, ExpectedIPs, ProxyPort       string
	ClashControllerURL, ClashSelector, ClashNode, TunnelInterface string
	DNSResolverURL, DNSBootstrapIP, ProbeURL, Programs, BundleIDs string
	AutoRecover                                                   bool
}

func draftFrom(c model.Config) Draft {
	return Draft{Mode: c.Mode, EnforcementMode: c.EnforcementMode, ProxyURL: c.ProxyURL,
		ExpectedIPs: strings.Join(c.ExpectedIPs, "\n"), ProxyPort: strconv.Itoa(int(c.ProxyPort)),
		ClashControllerURL: c.ClashControllerURL, ClashSelector: c.ClashSelector, ClashNode: c.ClashNode,
		TunnelInterface: c.TunnelInterface, DNSResolverURL: c.DNSResolverURL, DNSBootstrapIP: c.DNSBootstrapIP,
		ProbeURL: c.ProbeURL, Programs: strings.Join(c.Programs, "\n"), BundleIDs: strings.Join(c.BundleIDs, "\n"), AutoRecover: c.AutoRecover}
}

func splitLines(s string) []string {
	var values []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		if p = strings.TrimSpace(p); p != "" {
			values = append(values, p)
		}
	}
	return values
}

func (d Draft) config() (model.Config, error) {
	port, err := strconv.Atoi(strings.TrimSpace(d.ProxyPort))
	if err != nil || port < 1 || port > 65535 {
		return model.Config{}, errors.New("守护端口须为 1 至 65535；运行中请保持原端口")
	}
	return model.Config{Mode: d.Mode, EnforcementMode: d.EnforcementMode, ProxyURL: strings.TrimSpace(d.ProxyURL),
		ExpectedIPs: splitLines(d.ExpectedIPs), ProxyPort: uint16(port), ClashControllerURL: strings.TrimSpace(d.ClashControllerURL),
		ClashSelector: strings.TrimSpace(d.ClashSelector), ClashNode: strings.TrimSpace(d.ClashNode), TunnelInterface: strings.TrimSpace(d.TunnelInterface),
		DNSResolverURL: strings.TrimSpace(d.DNSResolverURL), DNSBootstrapIP: strings.TrimSpace(d.DNSBootstrapIP), ProbeURL: strings.TrimSpace(d.ProbeURL),
		Programs: splitLines(d.Programs), BundleIDs: splitLines(d.BundleIDs), AutoRecover: d.EnforcementMode == "proxy-only" && d.AutoRecover}, nil
}

// Controller fields belong to the UI thread. Only immutable action inputs are
// copied into goroutines; their completion is delivered through post (Update).
type Controller struct {
	core                                                    Core
	ops                                                     Operations
	ctx                                                     context.Context
	cancel                                                  context.CancelFunc
	post                                                    func(func())
	cancelAction                                            context.CancelFunc
	actionID, epoch, draftRevision                          uint64
	closed                                                  bool
	Config                                                  model.Config
	Status                                                  model.Status
	Events                                                  []model.Event
	Draft                                                   Draft
	startupDraftBase                                        Draft
	Dirty, Busy                                             bool
	Page, Notice, Candidate                                 string
	Username, Password, Secret                              string
	Remember                                                bool
	Apps                                                    []legacy.DesktopApplication
	BrowserPath, ClaudePath                                 string
	ScopeAck, PreviewAck                                    bool
	PreviewTarget, PreviewPath                              string
	Profiles                                                []model.RemoteProfile
	ProfileDraft                                            ProfileDraft
	ProfileDirty                                            bool
	profileRevision                                         uint64
	ProfileError, OverviewProfileID                         string
	PendingProfileAction, PendingProfileID, DeleteProfileID string
	Advanced                                                bool
}

func NewController(ctx context.Context, core Core, post func(func()), ops Operations) *Controller {
	c := newController(ctx, core, post, ops)
	c.InitializeProfiles()
	return c
}

// Startup uses this constructor before the background migration has completed.
// It reads ordinary snapshots only; the profile library is read after Ensure.
func newController(ctx context.Context, core Core, post func(func()), ops Operations) *Controller {
	ctx, cancel := context.WithCancel(ctx)
	if ops.Discover == nil {
		ops.Discover = legacy.DiscoverApplications
	}
	if ops.Launch == nil {
		ops.Launch = legacy.LaunchApplication
	}
	c := &Controller{core: core, ops: ops, ctx: ctx, cancel: cancel, post: post, Page: "出口概览", PreviewTarget: "chrome"}
	c.Config, c.Status, c.Events = core.Config(), core.Status(), core.Events()
	c.Draft = draftFrom(c.Config)
	c.startupDraftBase = c.Draft
	c.ProfileDraft = blankProfileDraft()
	c.Remember = c.Status.UpstreamCredentialsSaved
	return c
}

// Refresh reads only nonsecret core snapshots, never replacing an editing model.
func (c *Controller) refreshCurrentState() {
	config := c.core.Config()
	if config.Mode != c.Config.Mode || config.ProxyURL != c.Config.ProxyURL {
		// Endpoint binding also applies if Pause suppressed a Save completion.
		// Never leave a typed old account ready for submission to a new server.
		c.Username, c.Password, c.Remember, c.Candidate = "", "", false, ""
	}
	c.Config, c.Status, c.Events = config, c.core.Status(), c.core.Events()
}

func (c *Controller) Refresh() {
	c.refreshCurrentState()
	profiles, err := c.core.RemoteProfiles()
	if err != nil {
		c.ProfileError = "无法读取已保存代理；连接保持关闭，请检查本机代理配置文件后重新打开应用"
		c.Profiles = nil
		return
	}
	c.ProfileError, c.Profiles = "", profiles
}
func (c *Controller) MarkDirty() { c.Dirty = true; c.draftRevision++ }

// begin serializes ordinary actions, but Pause deliberately does not use this
// slot. A canceled action keeps its slot until it exits, preventing old work
// from racing a newer command. A final Disarm preserves Pause for non-context
// core mutations too; no newer action can have started at that point.
func (c *Controller) begin(work func(context.Context) (func(), error), success string) bool {
	return c.beginSettled(func(ctx context.Context) (func(), func(), error) {
		apply, err := work(ctx)
		return apply, nil, err
	}, success)
}

// A settlement only reconciles metadata already persisted by an action. Unlike
// a success callback it also runs after Pause, without changing Pause's notice
// or admitting any traffic. Ordinary operations never supply one.
func (c *Controller) beginSettled(work func(context.Context) (func(), func(), error), success string) bool {
	if c.closed || c.Busy {
		return false
	}
	c.Busy = true
	c.actionID++
	id, epoch := c.actionID, c.epoch
	ctx, cancel := context.WithCancel(c.ctx)
	c.cancelAction = cancel
	go func() {
		var apply, settle func()
		var err error
		if err = ctx.Err(); err == nil {
			apply, settle, err = work(ctx)
		}
		canceled := ctx.Err() != nil
		if canceled {
			c.core.Disarm()
		}
		cancel()
		c.post(func() {
			if c.closed || c.actionID != id {
				return
			}
			c.Busy = false
			c.cancelAction = nil
			c.Refresh()
			if err == nil && settle != nil {
				settle()
			}
			if c.epoch != epoch || canceled {
				return
			}
			if err != nil {
				c.Notice = err.Error()
				return
			}
			if apply != nil {
				apply()
			}
			c.Notice = success
		})
	}()
	return true
}

func (c *Controller) unchanged() bool {
	if c.ProfileError != "" {
		c.Notice = c.ProfileError
		return false
	}
	if c.Dirty || c.ProfileDirty {
		c.Notice = "有未保存的修改；请先保存或放弃修改，再检查、启动或使用代理"
		return false
	}
	return true
}
func (c *Controller) Check() {
	if !c.unchanged() {
		return
	}
	c.begin(func(ctx context.Context) (func(), error) { return nil, c.core.Check(ctx) }, "检查已完成；请核对出口后明确启用")
}
func (c *Controller) Arm() {
	if !c.unchanged() {
		return
	}
	c.begin(func(ctx context.Context) (func(), error) { return nil, c.core.Arm(ctx) }, "已提交启用；请核对当前状态与实际覆盖范围")
}
func (c *Controller) ProbeCandidate() {
	if !c.unchanged() {
		return
	}
	c.begin(func(ctx context.Context) (func(), error) {
		ip, err := c.core.ProbeCandidate(ctx)
		return func() { c.Candidate = ip }, err
	}, "候选值仅代表守护进程出口；确认固定性后手动填写期望 IP 并保存")
}
func (c *Controller) Pause() {
	c.epoch++
	if c.cancelAction != nil {
		c.cancelAction()
	}
	c.core.Disarm()
	c.Refresh()
	c.Notice = "已暂停转发并关闭本应用连接；已有系统规则需单独核对"
}
func (c *Controller) Save() {
	if c.Busy || c.closed {
		return
	}
	config, err := c.Draft.config()
	if err != nil {
		c.Notice = err.Error()
		return
	}
	revision := c.draftRevision
	detachProfile := c.Config.RemoteProfileID != "" && config.Mode != "remote"
	c.begin(func(context.Context) (func(), error) {
		if detachProfile {
			if err := c.core.SelectRemoteProfile(""); err != nil {
				return nil, err
			}
		}
		err := c.core.SaveConfig(config)
		return func() {
			if c.draftRevision == revision {
				c.Draft = draftFrom(c.Config)
				c.Dirty = false
			}
		}, err
	}, "设置已保存，会话已暂停；更换服务器会清除旧账户，请核对后重新检查")
}
func (c *Controller) SaveCredentials() {
	if !c.unchanged() || c.Busy || c.closed {
		return
	}
	if c.Username == "" && c.Password == "" {
		c.Notice = "未填写新账户；已有账户保留，需要清除请使用清除按钮"
		return
	}
	username, password, remember := c.Username, c.Password, c.Remember
	c.Username, c.Password = "", ""
	c.begin(func(context.Context) (func(), error) {
		if err := c.core.SetProxyCredentialsWithRemember(username, password, remember); err != nil {
			return nil, errors.New("账户提交或本机保存失败；输入已清空，请核对服务器和账户状态后重试")
		}
		return nil, nil
	}, "账户已更新，输入已清空；需要重新检查并手动启动")
}
func (c *Controller) ClearCredentials() {
	if c.Busy || c.closed {
		return
	}
	c.Username, c.Password = "", ""
	c.Remember = false
	c.begin(func(context.Context) (func(), error) {
		if err := c.core.SetProxyCredentials("", ""); err != nil {
			return nil, errors.New("账户未能完全清除，本机记录可能仍保留；请核对状态并重试")
		}
		return nil, nil
	}, "本次运行及本机保存的账户已清除；需要重新检查")
}
func (c *Controller) SaveSecret() {
	if !c.unchanged() || c.Busy || c.closed {
		return
	}
	secret := c.Secret
	c.Secret = ""
	c.begin(func(context.Context) (func(), error) { c.core.SetSecret(secret); return nil, nil }, "控制密钥仅供本次运行使用，输入已清空；需要重新检查")
}
func (c *Controller) Discover() {
	c.begin(func(ctx context.Context) (func(), error) {
		apps := c.ops.Discover(ctx)
		return func() { c.Apps = apps }, nil
	}, "应用发现已完成；未列出的应用可手动填写完整程序路径")
}
func (c *Controller) Launch(kind string) {
	if !c.unchanged() {
		return
	}
	path := c.BrowserPath
	if kind == "claude" {
		path = c.ClaudePath
	}
	if path == "" {
		c.Notice = "请显式选择应用或填写完整程序路径"
		return
	}
	revision := c.Status.SessionRevision
	request := legacy.LaunchRequest{Kind: kind, Path: path, SessionRevision: &revision, AcknowledgeProgramScope: c.ScopeAck}
	c.begin(func(context.Context) (func(), error) { return nil, c.ops.Launch(c.core, request) }, "已提交应用启动；请在目标设备验证出口、断线与真实客户端行为")
}
func (c *Controller) LaunchPreview() {
	if !c.unchanged() {
		return
	}
	path, target, revision, ack := c.PreviewPath, c.PreviewTarget, c.Status.SessionRevision, c.PreviewAck
	c.begin(func(ctx context.Context) (func(), error) {
		return nil, c.core.LaunchNativePreview(ctx, target, path, revision, ack)
	}, "已提交应用保护试用；尚未完成 Windows 实机验收")
}
func (c *Controller) Close() {
	if c.closed {
		return
	}
	c.closed = true
	c.cancel()
	if c.cancelAction != nil {
		c.cancelAction()
	}
	c.Username, c.Password, c.Secret = "", "", ""
	c.ProfileDraft.Username, c.ProfileDraft.Password = "", ""
	c.core.Disarm()
}

func (c *Controller) Poll(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.post(func() {
				if !c.closed {
					c.Refresh()
				}
			})
		}
	}
}

func (c *Controller) choices(kind, current string) []string {
	options := []string{"请选择应用"}
	seen := map[string]bool{}
	add := func(path string) {
		if path != "" && !seen[path] {
			seen[path] = true
			options = append(options, path)
		}
	}
	for _, app := range c.Apps {
		if app.Kind == kind {
			add(app.Path)
		}
	}
	for _, path := range c.Config.Programs {
		base := strings.ToLower(filepath.Base(path))
		if kind == "browser" && (base == "chrome.exe" || base == "msedge.exe" || base == "google chrome" || base == "microsoft edge") {
			add(path)
		}
		if kind == "claude" && (base == "claude" || base == "claude.exe") {
			add(path)
		}
	}
	add(current)
	return options
}
func (c *Controller) running() bool {
	return c.Config.EnforcementMode == c.Status.EnforcementMode && ((c.Config.EnforcementMode == "proxy-only" && c.Status.State == "proxy_active" && !c.Status.FilterActive) || (c.Config.EnforcementMode == "required" && c.Status.State == "armed" && c.Status.FilterActive))
}
func platformName(s string) string {
	if s == "darwin" {
		return "macOS"
	}
	if s == "windows" {
		return "Windows"
	}
	return s
}
func stateLabel(s string) string {
	switch s {
	case "unconfigured":
		return "尚未配置"
	case "checking":
		return "正在检查"
	case "recovering":
		return "转发已暂停 · 正在恢复"
	case "blocked":
		return "连接已关闭"
	case "ready":
		return "严格检查通过"
	case "armed":
		return "严格阻断已启用"
	case "proxy_ready":
		return "代理检查通过"
	case "proxy_active":
		return "代理转发已启动"
	case "stopped":
		return "已暂停"
	}
	return "状态未知"
}
func (c *Controller) summary() string {
	return fmt.Sprintf("%s · %s · %s", platformName(runtime.GOOS), stateLabel(c.Status.State), c.Status.ProxyAddress)
}
