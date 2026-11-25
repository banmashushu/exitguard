package desktop

import (
	"fmt"

	native "github.com/egoist/mygo/ui"
)

func (c *Controller) subscriptionsView(ctx *native.Context) {
	t := ctx.Theme()
	native.Text(ctx, "订阅与第一跳节点").FontSize(23).Bold().Role(native.RoleHeading).Level(1)
	native.Text(ctx, "ExitGuard 导入订阅并管理独立内核。请在代理设置选择节点作为第一跳，仍经原固定代理核验最终 IP；不会自动换节点或启用系统代理。").FontSize(12).TextColor(t.TextMuted)
	native.Column(ctx.Key("subscription-import")).FillWidth().Padding(16).Gap(10).Background(t.Surface).Radius(10).Children(func() {
		native.Text(ctx, "新增或替换订阅").FontSize(17).Bold()
		target, targets, targetIDs := "新增订阅", []string{"新增订阅"}, map[string]string{}
		for i, s := range c.Subscriptions {
			label := fmt.Sprintf("替换 %d · %s", i+1, s.Name)
			targets = append(targets, label)
			targetIDs[label] = s.ID
			if c.SubscriptionDraft.ID == s.ID {
				target = label
			}
		}
		native.Field(ctx, "导入目标", func() {
			native.Select(ctx.Key("subscription-import-target"), &target, targets).Label("导入目标").FillWidth().OnChange(func() {
				c.SubscriptionDraft.ID = targetIDs[target]
				if s, ok := c.subscription(c.SubscriptionDraft.ID); ok && c.SubscriptionDraft.Name == "" {
					c.SubscriptionDraft.Name = s.Name
				}
				c.MarkSubscriptionDirty()
			})
		})
		native.Field(ctx, "订阅名称", func() {
			native.TextInput(ctx.Key("subscription-name"), &c.SubscriptionDraft.Name).Label("订阅名称").OnChange(c.MarkSubscriptionDirty)
		})
		selected := map[string]string{"url": "私密 HTTPS 链接", "file": "本机订阅文件"}[c.SubscriptionDraft.SourceKind]
		native.Field(ctx, "导入方式", func() {
			native.Select(ctx.Key("subscription-source-kind"), &selected, []string{"私密 HTTPS 链接", "本机订阅文件"}).Label("导入方式").FillWidth().OnChange(func() {
				if selected == "本机订阅文件" {
					c.SubscriptionDraft.SourceKind = "file"
					c.SubscriptionDraft.DownloadRoute = "direct"
				} else {
					c.SubscriptionDraft.SourceKind = "url"
				}
				c.MarkSubscriptionDirty()
			})
		})
		if c.SubscriptionDraft.SourceKind == "file" {
			native.Field(ctx, "本机订阅文件完整路径", func() {
				native.TextInput(ctx.Key("subscription-file-path"), &c.SubscriptionDraft.FilePath).Label("本机订阅文件完整路径").OnChange(c.MarkSubscriptionDirty)
			})
			native.Text(ctx, "读取你明确指定的不超过 5 MiB 的本机文件；内容仅交给 ExitGuard 自身解析，不上传到转换服务。更新已有订阅时，请在导入目标选择替换。").FontSize(11).TextColor(t.TextMuted)
		} else {
			downloadRoute := subscriptionDownloadRouteLabel(c.SubscriptionDraft.DownloadRoute)
			native.Field(ctx, "下载路径", func() {
				native.Select(ctx.Key("subscription-download-route"), &downloadRoute, []string{"直接下载", "通过当前出口下载"}).Label("下载路径").FillWidth().OnChange(func() {
					c.SubscriptionDraft.DownloadRoute = "direct"
					if downloadRoute == "通过当前出口下载" {
						c.SubscriptionDraft.DownloadRoute = "active_exitguard"
					}
					c.MarkSubscriptionDirty()
				})
			})
			native.Text(ctx, "通过当前出口下载仅使用已启动并核验的现有连接；不会启动、恢复代理，也不会在失败后直接下载。").FontSize(11).TextColor(t.TextMuted)
			native.Field(ctx, "私密订阅链接（HTTPS）", func() {
				native.TextInput(ctx.Key("subscription-url"), &c.SubscriptionDraft.URL).Password().Label("私密订阅链接（HTTPS）").OnChange(c.MarkSubscriptionDirty)
			})
			native.Text(ctx, "链接可能含访问令牌，提交后清空且不会回填。下载失败时可先取得订阅文件，再选择本机文件导入。").FontSize(11).TextColor(t.TextMuted)
		}
		native.PrimaryButton(ctx.Key("subscription-import-submit"), "导入订阅").Disabled(c.Busy).OnClick(c.ImportSubscription)
		native.Text(ctx, "订阅来源和节点账户随配置明文保存在此设备；导入不会选择节点或启动连接，替换正在使用的订阅会暂停连接。").FontSize(11).TextColor(t.TextMuted)
	})
	native.Row(ctx).Gap(10).Children(func() {
		native.Text(ctx, fmt.Sprintf("本机订阅（%d）", len(c.Subscriptions))).FontSize(17).Bold().Grow(1)
		native.Button(ctx.Key("subscription-reload"), "载入本机列表").Disabled(c.Busy).OnClick(c.LoadSubscriptions)
	})
	if !c.SubscriptionsLoaded {
		native.Text(ctx, "正在载入或尚未载入本机列表；不会自动下载订阅。").FontSize(12).TextColor(t.TextMuted)
	}
	for _, s := range c.Subscriptions {
		native.Column(ctx.Key("subscription-" + s.ID)).FillWidth().Padding(12).Gap(7).Background(t.Surface).Radius(8).Children(func() {
			native.Text(ctx, s.Name).Bold()
			kind := "本机文件"
			if s.SourceKind == "url" {
				kind = "私密链接"
			}
			native.Text(ctx, fmt.Sprintf("%s · 可选 %d / 共 %d 个节点 · 更新 %s", kind, s.SupportedNodeCount, s.NodeCount, or(s.UpdatedAt, "时间未知"))).FontSize(12).TextColor(t.TextMuted)
			if s.SourceKind == "url" {
				native.Text(ctx, "上次成功的下载路径："+subscriptionDownloadRouteLabel(s.DownloadRoute)).FontSize(12).TextColor(t.TextMuted)
			}
			native.Row(ctx).Gap(8).Wrap().Children(func() {
				native.Button(ctx.Key("subscription-view-"+s.ID), "查看节点 · "+s.Name).Disabled(c.Busy).OnClick(func() { c.ViewSubscription(s.ID) })
				if s.SourceKind == "url" {
					native.Button(ctx.Key("subscription-refresh-"+s.ID), "直接更新订阅 · "+s.Name).Disabled(c.Busy).OnClick(func() { c.RefreshSubscription(s.ID) })
					native.Button(ctx.Key("subscription-refresh-active-"+s.ID), "通过当前出口更新 · "+s.Name).Disabled(c.Busy).OnClick(func() { c.RefreshSubscriptionViaActive(s.ID) })
				}
				native.Button(ctx.Key("subscription-delete-"+s.ID), "删除订阅 · "+s.Name).Disabled(c.Busy).OnClick(func() { c.RequestDeleteSubscription(s.ID) })
			})
			if c.DeleteSubscriptionID == s.ID {
				native.Text(ctx, "确认删除此订阅及节点？被代理配置引用的订阅须先解除引用。").FontSize(12).TextColor(t.Warning)
				native.Row(ctx).Gap(8).Children(func() {
					native.Button(ctx.Key("subscription-delete-confirm"), "确认删除订阅").Disabled(c.Busy).OnClick(c.ConfirmDeleteSubscription)
					native.Button(ctx.Key("subscription-delete-cancel"), "取消删除订阅").OnClick(func() { c.DeleteSubscriptionID = "" })
				})
			}
		})
	}
	if s, ok := c.subscription(c.ViewedSubscriptionID); ok {
		native.Text(ctx, "节点列表 · "+s.Name).FontSize(17).Bold()
		native.Text(ctx, "可选表示符合 ExitGuard 的能力范围，尚未核验连通性；请到代理设置选为第一跳，再检查出口。").FontSize(12).TextColor(t.TextMuted)
		native.Scroll(ctx.Key("subscription-nodes")).Height(320).FillWidth().Gap(8).Children(func() {
			for i, n := range c.SubscriptionNodes[s.ID] {
				native.Column(ctx.Key(fmt.Sprintf("subscription-node-%d-%s", i, n.ID))).FillWidth().Padding(10).Gap(4).Background(t.Surface).Radius(6).Children(func() {
					native.Text(ctx, n.Name+" · "+n.Type).Bold()
					if n.Supported {
						if n.SkipsTLSVerification {
							native.Text(ctx, "可选择；节点按订阅设置跳过证书验证").FontSize(12).TextColor(t.Warning)
						} else {
							native.Text(ctx, "可选择；使用前需检查出口").FontSize(12).TextColor(t.Success)
						}
					} else {
						native.Text(ctx, "ExitGuard 暂不可选择："+n.Reason).FontSize(12).TextColor(t.Warning)
					}
				})
			}
		})
	}
}

func subscriptionDownloadRouteLabel(route string) string {
	if route == "active_exitguard" {
		return "通过当前出口下载"
	}
	return "直接下载"
}
