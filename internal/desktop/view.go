package desktop

import (
	"fmt"
	"runtime"
	"strings"

	native "github.com/egoist/mygo/ui"
)

var sourceLabels = map[string]string{"remote": "远程代理", "proxy": "本地固定专用入口", "feilian": "公司飞连", "clash": "Clash / Mihomo（只读）"}
var protectionLabels = map[string]string{"proxy-only": "仅代理转发", "required": "严格阻断"}

func (c *Controller) View(ctx *native.Context) {
	t := ctx.Theme()
	native.Row(ctx).Fill().Gap(0).Children(func() {
		native.Column(ctx.Key("sidebar")).Width(190).FillHeight().Padding(20).Gap(14).Background(t.Surface).Children(func() {
			native.Text(ctx, "ExitGuard").FontSize(25).Bold()
			native.Text(ctx, "固定出口 · 本机代理").FontSize(12).TextColor(t.TextMuted)
			native.Divider(ctx)
			for _, page := range []string{"出口概览", "代理设置", "诊断与事件"} {
				native.Button(ctx.Key(page), page).FillWidth().OnClick(func() { c.Page = page })
			}
			native.Spacer(ctx)
			native.Text(ctx, "仅在此设备运行").FontSize(12)
			native.Text(ctx, "账户可保存本机\n无云端同步").FontSize(11).TextColor(t.TextMuted)
		})
		native.Column(ctx.Key("main")).Grow(1).FillHeight().Children(func() {
			native.Row(ctx).Padding(18, 24).Gap(12).Children(func() {
				native.Text(ctx, c.Page).FontSize(20).Bold().Grow(1)
				native.Text(ctx, platformName(c.Status.Platform)+" · 本机").TextColor(t.TextMuted)
				native.Button(ctx.Key("refresh"), "刷新状态").OnClick(c.Refresh)
			})
			native.Divider(ctx)
			native.Scroll(ctx.Key("page-content")).Grow(1).FillWidth().Padding(24).Gap(18).Children(func() {
				native.Text(ctx, "普通代理可独立运行。严格阻断仍需系统过滤部署与真实设备验收。").FontSize(12).TextColor(t.TextMuted)
				if c.Notice != "" {
					native.Text(ctx, c.Notice).Padding(12).Background(t.Surface).Role(native.RoleStatus)
				}
				if c.ProfileError != "" {
					native.Text(ctx, c.ProfileError).TextColor(t.Danger)
				}
				if c.Dirty || c.ProfileDirty {
					native.Text(ctx, "有未保存的修改；请先保存或放弃修改。暂停始终可用。").TextColor(t.Warning)
				}
				if c.Dirty {
					native.Button(ctx.Key("save-advanced-dirty"), "保存高级修改").Disabled(c.Busy || c.ProfileDirty).OnClick(c.Save)
				}
				switch c.Page {
				case "代理设置":
					c.settings(ctx)
				case "诊断与事件":
					c.diagnostics(ctx)
				default:
					c.overview(ctx)
				}
			})
		})
	})
}

func (c *Controller) overview(ctx *native.Context) {
	t := ctx.Theme()
	color := t.TextMuted
	switch c.Status.State {
	case "armed":
		color = t.Success
	case "proxy_active":
		color = t.Accent
	case "blocked":
		color = t.Danger
	case "recovering", "checking":
		color = t.Warning
	}
	native.Column(ctx.Key("status")).Padding(20).Gap(10).Background(t.Surface).Radius(12).Children(func() {
		native.Text(ctx, "当前使用："+c.activeProfileName()).FontSize(15).Bold()
		native.Text(ctx, stateLabel(c.Status.State)).FontSize(24).Bold().TextColor(color).Role(native.RoleHeading).Level(1)
		native.Text(ctx, c.Status.Reason)
		native.Text(ctx, "本机入口："+c.Status.ProxyAddress).FontSize(13).TextColor(t.TextMuted)
		if c.Status.State == "recovering" {
			native.Text(ctx, fmt.Sprintf("恢复核验 %d / %d · 下次检查 %s", c.Status.RecoveryAttempt, c.Status.RecoveryMaxAttempts, c.Status.NextRetryAt)).TextColor(t.Warning)
		}
		native.Row(ctx).Gap(8).Wrap().Children(func() {
			native.Button(ctx.Key("check"), "检查出口").Disabled(c.Busy || c.Dirty || c.ProfileDirty).OnClick(c.Check)
			native.Button(ctx.Key("candidate"), "测试候选 IP").Disabled(c.Busy || c.Dirty || c.ProfileDirty).OnClick(c.ProbeCandidate)
			label := "启动代理"
			if c.Config.EnforcementMode == "required" {
				label = "启用严格阻断"
			}
			ready := c.Status.State == "proxy_ready" || c.Status.State == "ready"
			native.PrimaryButton(ctx.Key("arm"), label).Disabled(c.Busy || c.Dirty || c.ProfileDirty || !ready).OnClick(c.Arm)
			native.Button(ctx.Key("pause"), "暂停转发").OnClick(c.Pause)
		})
		native.Text(ctx, "检查或候选探测会暂停当前连接；仅查看状态请用“刷新状态”。").FontSize(12).TextColor(t.TextMuted)
	})
	if len(c.Profiles) > 0 {
		c.profileOverviewChoice(ctx)
	}
	native.Row(ctx).Gap(16).Wrap().Children(func() {
		metric := func(title, value string) {
			native.Column(ctx).MinWidth(180).Grow(1).Gap(6).Children(func() {
				native.Text(ctx, title).FontSize(12).TextColor(t.TextMuted)
				native.Text(ctx, value).FontSize(17).Bold()
			})
		}
		metric("出口来源", sourceLabels[c.Config.Mode])
		metric("期望公网 IPv4", or(strings.Join(c.Config.ExpectedIPs, " / "), "未设置"))
		metric("最近观察到的 IP", or(c.Status.ObservedIP, "尚未观察"))
	})
	if c.Candidate != "" {
		native.Text(ctx, "候选出口："+c.Candidate+"。仅代表守护进程出口，未保存为期望 IP；请向提供方确认固定性。").TextColor(t.Warning)
	}
	native.Text(ctx, c.coverage()).FontSize(13).TextColor(t.TextMuted)
	c.clients(ctx)
}

func (c *Controller) clients(ctx *native.Context) {
	t := ctx.Theme()
	native.Column(ctx.Key("clients")).Padding(18).Gap(12).Background(t.Surface).Radius(12).Children(func() {
		native.Row(ctx).Gap(12).Children(func() {
			native.Text(ctx, "通过代理启动").FontSize(18).Bold().Grow(1)
			native.Button(ctx.Key("discover"), "重新发现应用").Disabled(c.Busy).OnClick(c.Discover)
		})
		native.Text(ctx, "发现只表示安装信息。选择后才会启动；未发现时可手动填写实际可执行文件的完整路径。").FontSize(12).TextColor(t.TextMuted)
		if len(c.Apps) > 0 {
			for _, app := range c.Apps {
				native.Text(ctx, app.Name+" · "+app.Path).FontSize(11).TextColor(t.TextMuted)
			}
		}
		c.appChoice(ctx, "browser", "选择浏览器", &c.BrowserPath)
		native.Field(ctx, "浏览器完整路径", func() { native.TextInput(ctx.Key("browser-manual"), &c.BrowserPath).Label("浏览器完整路径") })
		native.Button(ctx.Key("launch-browser"), "启动独立浏览器").Disabled(c.Busy || c.Dirty || c.ProfileDirty || !c.running()).OnClick(func() { c.Launch("browser") })
		c.appChoice(ctx, "claude", "选择 Claude Desktop", &c.ClaudePath)
		native.Field(ctx, "Claude 完整路径", func() { native.TextInput(ctx.Key("claude-manual"), &c.ClaudePath).Label("Claude 完整路径") })
		native.Button(ctx.Key("launch-claude"), "启动 Claude Desktop").Disabled(c.Busy || c.Dirty || c.ProfileDirty || !c.running()).OnClick(func() { c.Launch("claude") })
		native.Text(ctx, "Claude Desktop 的登录、聊天、上传与版本兼容性仍需实测；不声明 Claude Code 标签页或全部系统流量已受保护。").FontSize(12).TextColor(t.TextMuted)
		if c.Config.EnforcementMode == "required" {
			native.Checkbox(ctx.Key("scope-ack"), &c.ScopeAck, "我理解程序级过滤会影响同一程序的全部窗口，并已核对辅助进程范围")
		}
		if runtime.GOOS == "windows" {
			native.Divider(ctx)
			native.Text(ctx, "Windows 应用保护试用").Bold()
			native.Text(ctx, "本发行包未包含应用保护预览工具。此功能需另行部署 Sandboxie 和配套预览工具，尚未完成 Windows 实机验收；当前入口不可用。").FontSize(12).TextColor(t.Warning)
			if c.Status.NativeReason != "" {
				native.Text(ctx, c.Status.NativeReason).FontSize(12).TextColor(t.TextMuted)
			}
			native.Button(ctx.Key("preview-launch"), "应用保护试用（需另行部署）").Disabled(true)
		}
	})
}

func (c *Controller) appChoice(ctx *native.Context, kind, label string, path *string) {
	selected := or(*path, "请选择应用")
	native.Field(ctx, label, func() {
		native.Select(ctx.Key(kind+"-choices"), &selected, c.choices(kind, *path)).Label(label).OnChange(func() {
			if selected == "请选择应用" {
				*path = ""
			} else {
				*path = selected
			}
		})
	})
}

func (c *Controller) field(ctx *native.Context, key, label string, value *string) {
	native.Field(ctx, label, func() { native.TextInput(ctx.Key(key), value).Label(label).OnChange(c.MarkDirty) })
}
func (c *Controller) selectConfig(ctx *native.Context, key, label string, value *string, labels map[string]string, ids []string) {
	selected := labels[*value]
	options := make([]string, 0, len(ids))
	for _, id := range ids {
		options = append(options, labels[id])
	}
	native.Field(ctx, label, func() {
		native.Select(ctx.Key(key), &selected, options).Label(label).OnChange(func() {
			for _, id := range ids {
				if labels[id] == selected {
					*value = id
					c.MarkDirty()
					return
				}
			}
		})
	})
}

func (c *Controller) settings(ctx *native.Context) {
	t := ctx.Theme()
	native.Text(ctx, "代理设置").FontSize(23).Bold().Role(native.RoleHeading).Level(1)
	c.selectConfig(ctx, "source", "出口来源", &c.Draft.Mode, sourceLabels, []string{"remote", "proxy", "feilian", "clash"})
	if c.Draft.Mode == "remote" {
		c.profilesView(ctx)
	} else {
		if c.Draft.Mode == "proxy" || c.Draft.Mode == "clash" {
			c.field(ctx, "proxy-url", "代理服务器", &c.Draft.ProxyURL)
		}
		c.field(ctx, "expected", "期望公网 IPv4（多个用逗号分隔）", &c.Draft.ExpectedIPs)
		if c.Draft.Mode == "feilian" {
			c.field(ctx, "tunnel", "飞连隧道接口", &c.Draft.TunnelInterface)
		}
		if c.Draft.Mode == "clash" {
			c.field(ctx, "clash-controller", "Clash 控制接口", &c.Draft.ClashControllerURL)
			c.field(ctx, "selector", "专用策略", &c.Draft.ClashSelector)
			c.field(ctx, "node", "固定节点", &c.Draft.ClashNode)
			native.Field(ctx, "Clash 控制密钥", func() { native.TextInput(ctx.Key("clash-secret"), &c.Secret).Password().Label("Clash 控制密钥") })
			native.Button(ctx.Key("save-secret"), "提交本次控制密钥").Disabled(c.Busy || c.Dirty || c.ProfileDirty).OnClick(c.SaveSecret)
		}
		native.PrimaryButton(ctx.Key("save-config-top"), "保存设置").Disabled(c.Busy || c.ProfileDirty).OnClick(c.Save)
	}
	native.Button(ctx.Key("advanced-toggle"), map[bool]string{false: "高级设置", true: "收起高级设置"}[c.Advanced]).OnClick(func() { c.Advanced = !c.Advanced })
	if !c.Advanced {
		return
	}
	native.Column(ctx.Key("advanced")).Padding(16).Gap(12).Background(t.Surface).Radius(10).Children(func() {
		c.selectConfig(ctx, "protection", "保护方式", &c.Draft.EnforcementMode, protectionLabels, []string{"proxy-only", "required"})
		native.Checkbox(ctx.Key("auto-recover"), &c.Draft.AutoRecover, "连接中断后核验同一路径和同一公网 IP，再恢复代理转发").Disabled(c.Draft.EnforcementMode != "proxy-only").OnChange(c.MarkDirty)
		native.Text(ctx, "保存不会安装或更改系统过滤。严格阻断仍需合格部署、实际策略证明与目标设备验收。").FontSize(12).TextColor(t.TextMuted)
		native.Field(ctx, "系统过滤程序路径（每行一个）", func() {
			native.TextArea(ctx.Key("programs"), &c.Draft.Programs).Height(110).Label("系统过滤程序路径").OnChange(c.MarkDirty)
		})
		native.Field(ctx, "macOS 应用标识（每行一个）", func() {
			native.TextArea(ctx.Key("bundle-ids"), &c.Draft.BundleIDs).Height(70).Label("macOS 应用标识").OnChange(c.MarkDirty)
		})
		c.field(ctx, "port", "本地守护端口", &c.Draft.ProxyPort)
		native.Text(ctx, "运行中不能更换守护端口；请保留当前值。").FontSize(12).TextColor(t.TextMuted)
		c.field(ctx, "probe-url", "公网 IP 探测地址（HTTPS）", &c.Draft.ProbeURL)
		c.field(ctx, "dns-url", "DNS over HTTPS 地址", &c.Draft.DNSResolverURL)
		c.field(ctx, "dns-bootstrap", "DNS 引导公网 IPv4", &c.Draft.DNSBootstrapIP)
		native.PrimaryButton(ctx.Key("save-config"), "保存高级设置").Disabled(c.Busy || c.ProfileDirty).OnClick(c.Save)
	})
}

func (c *Controller) credentialStatus() string {
	s := c.Status
	if !s.CredentialPersistenceSupported {
		return "当前平台仅支持本次运行的账户；退出后需重新提交。"
	}
	if s.UpstreamCredentialsRestored && s.UpstreamCredentialsSet {
		return "已从本机明文文件恢复账户；不显示账户或密码，仍需检查并手动启动。"
	}
	if s.UpstreamCredentialsSaved {
		if s.UpstreamCredentialsSet {
			return "账户已明文保存在此设备；仍需检查并手动启动。"
		}
		return "本机仍有保存账户，当前未载入；请重新提交或清除。"
	}
	if s.UpstreamCredentialsSet {
		return "账户仅供本次运行；重开后需重新提交。"
	}
	return "账户未提交；无需认证的代理可以留空。"
}
func (c *Controller) coverage() string {
	if c.Config.EnforcementMode == "proxy-only" {
		return "仅代理转发，系统防绕行未核验。本模式只转发遵循本机代理的 IPv4 TCP；忽略代理的连接与 UDP 不在范围内，也不会更改已有系统规则。"
	}
	return "严格阻断要求实际系统过滤与当前策略匹配；同一程序的所有窗口及辅助进程均需覆盖。真实断线、DNS、IPv6 与 UDP 行为仍须目标设备验收。"
}
func (c *Controller) diagnostics(ctx *native.Context) {
	t := ctx.Theme()
	native.Text(ctx, "诊断与事件").FontSize(23).Bold().Role(native.RoleHeading).Level(1)
	native.Text(ctx, "当前策略").Bold()
	native.Text(ctx, c.summary())
	native.Text(ctx, c.coverage()).TextColor(t.TextMuted)
	native.Text(ctx, "系统策略证明："+or(c.Status.PolicyHash, "无当前系统策略证明"))
	native.Text(ctx, "最近检查："+or(c.Status.CheckedAt, "尚未检查"))
	if c.Status.NativeReason != "" {
		native.Text(ctx, c.Status.NativeReason).TextColor(t.Warning)
	}
	native.Divider(ctx)
	native.Text(ctx, "本次运行事件").FontSize(17).Bold()
	if len(c.Events) == 0 {
		native.Text(ctx, "本次运行暂无事件").TextColor(t.TextMuted)
	}
	for i := len(c.Events) - 1; i >= 0; i-- {
		e := c.Events[i]
		native.Column(ctx.Key(fmt.Sprintf("event-%d", i))).Gap(4).Padding(10).Children(func() {
			native.Text(ctx, e.At+" · "+stateLabel(e.State)).FontSize(11).TextColor(t.TextMuted)
			native.Text(ctx, e.Message)
		})
	}
}
func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
