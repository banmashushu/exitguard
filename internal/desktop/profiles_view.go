package desktop

import (
	"fmt"
	"strings"

	native "github.com/egoist/mygo/ui"
)

func (c *Controller) profileField(ctx *native.Context, key, label string, value *string, password bool) {
	native.Field(ctx, label, func() {
		input := native.TextInput(ctx.Key(key), value).Label(label).OnChange(c.MarkProfileDirty)
		if password {
			input.Password()
		}
	})
}

func (c *Controller) profilesView(ctx *native.Context) {
	t := ctx.Theme()
	if c.ProfileError != "" {
		native.Text(ctx, c.ProfileError).TextColor(t.Danger)
		return
	}
	if c.PendingProfileAction != "" {
		native.Column(ctx.Key("discard-profile")).Padding(12).Gap(8).Background(t.Surface).Children(func() {
			native.Text(ctx, "当前代理有未保存的修改。放弃后才会更换正在编辑的代理。").TextColor(t.Warning)
			native.Row(ctx).Gap(8).Children(func() {
				native.Button(ctx.Key("discard-confirm"), "放弃修改并继续").Disabled(c.Busy).OnClick(c.DiscardProfileChanges)
				native.Button(ctx.Key("discard-cancel"), "继续编辑").OnClick(c.CancelProfileChange)
			})
		})
	}
	native.Row(ctx.Key("profiles-panel")).Gap(18).Children(func() {
		native.Column(ctx.Key("profile-library")).Width(270).Shrink(0).Gap(10).Children(func() {
			native.Row(ctx).Gap(8).Children(func() {
				native.Text(ctx, fmt.Sprintf("已保存代理（%d）", len(c.Profiles))).FontSize(17).Bold().Grow(1)
				native.Button(ctx.Key("profile-new"), "新建").Disabled(c.Busy).OnClick(c.NewProfile)
			})
			native.Text(ctx, "选择条目只进入编辑；切换连接请点“使用此代理”。").FontSize(12).TextColor(t.TextMuted)
			native.Scroll(ctx.Key("profile-list")).Height(350).FillWidth().Gap(8).Children(func() {
				if len(c.Profiles) == 0 {
					native.Text(ctx, "还没有保存的代理\n填写右侧表单并保存。").Padding(12).TextColor(t.TextMuted)
				}
				for _, p := range c.Profiles {
					native.Column(ctx.Key("profile-" + p.ID)).FillWidth().Padding(12).Gap(5).Background(t.Surface).Radius(8).Children(func() {
						native.Text(ctx, p.Name).Bold()
						native.Text(ctx, p.ProxyURL).FontSize(12).TextColor(t.TextMuted)
						if p.PreProxyURL != "" {
							native.Text(ctx, "经前置代理："+p.PreProxyURL).FontSize(11).TextColor(t.TextMuted)
						} else if p.ManagedSubscriptionID != "" {
							native.Text(ctx, "第一跳：内置订阅节点").FontSize(11).TextColor(t.TextMuted)
						}
						native.Text(ctx, "期望出口："+or(strings.Join(p.ExpectedIPs, " / "), "尚未填写")).FontSize(11).TextColor(t.TextMuted)
						account := "账户未保存"
						if p.HasCredentials {
							account = "账户已保存"
						}
						marks := []string{account}
						if p.ID == c.Config.RemoteProfileID {
							marks = append(marks, "当前使用")
						}
						if p.ID == c.ProfileDraft.ID {
							marks = append(marks, "正在编辑")
						}
						native.Text(ctx, strings.Join(marks, " · ")).FontSize(11).TextColor(t.Accent)
						native.Button(ctx.Key("edit-"+p.ID), "编辑 "+p.Name).Disabled(c.Busy).OnClick(func() { c.EditProfile(p.ID) })
					})
				}
			})
		})
		native.Column(ctx.Key("profile-editor")).Grow(1).Gap(10).Children(func() {
			label := "新建代理"
			if c.ProfileDraft.ID != "" {
				label = "正在编辑：" + c.ProfileDraft.Name
			}
			native.Text(ctx, label).FontSize(17).Bold()
			if c.ProfileDraft.ID == c.Config.RemoteProfileID && c.ProfileDraft.ID != "" {
				native.Text(ctx, "这是当前使用的代理；保存更改会暂停连接以便重新核验。").FontSize(12).TextColor(t.Warning)
			}
			c.profileField(ctx, "profile-name", "代理名称", &c.ProfileDraft.Name, false)
			native.Row(ctx).Gap(10).Children(func() {
				native.Column(ctx).Width(100).Shrink(0).Children(func() {
					selected := c.ProfileDraft.Protocol
					native.Field(ctx, "协议", func() {
						native.Select(ctx.Key("profile-protocol"), &selected, []string{"HTTPS", "SOCKS5", "HTTP"}).Label("协议").MinWidth(0).FillWidth().OnChange(func() { c.ProfileDraft.Protocol = selected; c.MarkProfileDirty() })
					})
				})
				native.Column(ctx).Grow(1).Children(func() { c.profileField(ctx, "profile-host", "服务器 / IP", &c.ProfileDraft.Host, false) })
				native.Column(ctx).Width(82).Shrink(0).Children(func() { c.profileField(ctx, "profile-port", "端口", &c.ProfileDraft.Port, false) })
			})
			native.Row(ctx).Gap(10).Children(func() {
				native.Column(ctx).Grow(1).Children(func() { c.profileField(ctx, "profile-username", "代理用户名", &c.ProfileDraft.Username, false) })
				native.Column(ctx).Grow(1).Children(func() { c.profileField(ctx, "profile-password", "代理密码", &c.ProfileDraft.Password, true) })
			})
			if c.ProfileDraft.HasCredentials {
				native.Text(ctx, "此代理已保存账户；用户名和密码都留空会保留。更换服务器时需替换或清除旧账户。").FontSize(12).TextColor(t.TextMuted)
				native.Checkbox(ctx.Key("profile-clear-account"), &c.ProfileDraft.ClearCredentials, "清除已保存账户（保存代理后生效）").OnChange(func() {
					if c.ProfileDraft.ClearCredentials {
						c.ProfileDraft.Username, c.ProfileDraft.Password = "", ""
					}
					c.MarkProfileDirty()
				})
			} else {
				native.Text(ctx, "无需认证可留空；新账户需要同时填写用户名和密码。").FontSize(12).TextColor(t.TextMuted)
			}
			c.preProxyFields(ctx)
			c.profileField(ctx, "profile-expected", "期望出口 IP（可先留空）", &c.ProfileDraft.ExpectedIPs, false)
			native.Text(ctx, "账户随代理配置明文保存在此设备；密码不会回填。HTTP / SOCKS5 链路本身不加密。").FontSize(11).TextColor(t.TextMuted)
			native.Row(ctx).Gap(8).Wrap().Children(func() {
				native.PrimaryButton(ctx.Key("profile-save"), "保存代理").Disabled(c.Busy).OnClick(c.SaveProfile)
				native.Button(ctx.Key("profile-use"), "使用此代理").Disabled(c.Busy || !c.canUseProfile() || c.ProfileDraft.ID == "" || !c.savedProfileNodeAvailable(c.ProfileDraft.ID)).OnClick(func() { c.UseProfile(c.ProfileDraft.ID) })
				native.Button(ctx.Key("profile-revert"), "放弃修改").Disabled(c.Busy || !c.ProfileDirty).OnClick(c.RevertProfile)
				native.Button(ctx.Key("profile-delete"), "删除代理").Disabled(c.Busy || c.ProfileDraft.ID == "").OnClick(func() { c.RequestDeleteProfile(c.ProfileDraft.ID) })
			})
			native.Text(ctx, "期望 IP 留空时：保存 → 使用此代理 → 到概览测试候选 IP → 确认后手动填写。不会自动采用候选值。").FontSize(11).TextColor(t.TextMuted)
			if c.DeleteProfileID != "" {
				name := "所选代理"
				if p, ok := c.profile(c.DeleteProfileID); ok {
					name = p.Name
				}
				native.Column(ctx.Key("profile-delete-confirmation")).Padding(12).Gap(8).Background(t.Surface).Children(func() {
					native.Text(ctx, "确认删除“"+name+"”及其已保存账户？未保存修改也会丢弃。删除当前代理会关闭连接。").TextColor(t.Warning)
					native.Row(ctx).Gap(8).Children(func() {
						native.Button(ctx.Key("profile-delete-confirm"), "确认删除").Disabled(c.Busy).OnClick(c.ConfirmDeleteProfile)
						native.Button(ctx.Key("profile-delete-cancel"), "取消删除").OnClick(c.CancelDeleteProfile)
					})
				})
			}
		})
	})
}

func (c *Controller) preProxyFields(ctx *native.Context) {
	t := ctx.Theme()
	native.Column(ctx.Key("preproxy-editor")).FillWidth().Padding(12).Gap(8).Background(t.Surface).Radius(8).Children(func() {
		selected := firstHopLabels[c.ProfileDraft.FirstHopSource]
		native.Field(ctx, "第一跳来源", func() {
			native.Select(ctx.Key("profile-firsthop-source"), &selected, []string{firstHopLabels["none"], firstHopLabels["proxy"], firstHopLabels["subscription"]}).Label("第一跳来源").FillWidth().OnChange(func() {
				for id, label := range firstHopLabels {
					if label == selected {
						c.ProfileDraft.FirstHopSource = id
						c.MarkProfileDirty()
						break
					}
				}
				if c.ProfileDraft.FirstHopSource == "subscription" && !c.SubscriptionsLoaded {
					c.LoadSubscriptions()
				}
			})
		})
		native.Text(ctx, "第一跳只用于连接上方固定出口；最终出口账户和期望 IP 仍由上方配置决定。编辑不会切换或启动连接。").FontSize(11).TextColor(t.TextMuted)
		if c.ProfileDraft.FirstHopSource == "subscription" {
			c.managedNodeFields(ctx)
			return
		}
		if c.ProfileDraft.FirstHopSource != "proxy" {
			native.Text(ctx, "选择不使用前置代理并保存，会清除已保存的第一跳地址、账户与订阅节点选择。").FontSize(11).TextColor(t.TextMuted)
			return
		}
		native.Text(ctx, "已有代理地址适用于本地或远程 HTTP(S)/SOCKS5 入口。要由 ExitGuard 导入订阅并管理内核，请选择“内置订阅节点”。").FontSize(11).TextColor(t.TextMuted)
		native.Row(ctx).Gap(10).Children(func() {
			native.Column(ctx).Width(110).Shrink(0).Children(func() {
				selected := c.ProfileDraft.PreProxyProtocol
				native.Field(ctx, "前置代理协议", func() {
					native.Select(ctx.Key("profile-preproxy-protocol"), &selected, []string{"HTTP", "HTTPS", "SOCKS5"}).Label("前置代理协议").MinWidth(0).FillWidth().OnChange(func() { c.ProfileDraft.PreProxyProtocol = selected; c.MarkProfileDirty() })
				})
			})
			native.Column(ctx).Grow(1).Children(func() {
				c.profileField(ctx, "profile-preproxy-host", "前置服务器", &c.ProfileDraft.PreProxyHost, false)
			})
			native.Column(ctx).Width(82).Shrink(0).Children(func() {
				c.profileField(ctx, "profile-preproxy-port", "前置端口", &c.ProfileDraft.PreProxyPort, false)
			})
		})
		native.Row(ctx).Gap(10).Children(func() {
			native.Column(ctx).Grow(1).Children(func() {
				c.profileField(ctx, "profile-preproxy-username", "前置代理用户名", &c.ProfileDraft.PreProxyUsername, false)
			})
			native.Column(ctx).Grow(1).Children(func() {
				c.profileField(ctx, "profile-preproxy-password", "前置代理密码", &c.ProfileDraft.PreProxyPassword, true)
			})
		})
		if c.ProfileDraft.HasPreProxyCredentials {
			native.Text(ctx, "前置账户已保存；两项都留空会保留。更换前置地址时需替换或清除该账户。").FontSize(11).TextColor(t.TextMuted)
			native.Checkbox(ctx.Key("profile-preproxy-clear-account"), &c.ProfileDraft.ClearPreProxyCredentials, "清除前置已保存账户（保存代理后生效）").OnChange(func() {
				if c.ProfileDraft.ClearPreProxyCredentials {
					c.ProfileDraft.PreProxyUsername, c.ProfileDraft.PreProxyPassword = "", ""
				}
				c.MarkProfileDirty()
			})
		} else {
			native.Text(ctx, "前置账户独立于固定出口账户；无需认证可留空，否则需成对填写。").FontSize(11).TextColor(t.TextMuted)
		}
	})
}

var firstHopLabels = map[string]string{"none": "不使用前置代理", "proxy": "已有代理地址", "subscription": "内置订阅节点"}

func (c *Controller) managedNodeFields(ctx *native.Context) {
	t := ctx.Theme()
	native.Row(ctx).Gap(8).Wrap().Children(func() {
		native.Button(ctx.Key("manage-subscriptions"), "管理订阅").OnClick(c.OpenSubscriptions)
		native.Button(ctx.Key("load-subscriptions"), "载入订阅列表").Disabled(c.Busy).OnClick(c.LoadSubscriptions)
	})
	if !c.SubscriptionsLoaded {
		native.Text(ctx, "先载入本机订阅列表，再明确选择订阅和节点；不会自动选择。").FontSize(11).TextColor(t.TextMuted)
		return
	}
	selected, options, ids := "请选择订阅", []string{}, map[string]string{}
	for i, s := range c.Subscriptions {
		label := fmt.Sprintf("%d · %s", i+1, s.Name)
		options = append(options, label)
		ids[label] = s.ID
		if s.ID == c.ProfileDraft.ManagedSubscriptionID {
			selected = label
		}
	}
	native.Field(ctx, "第一跳订阅", func() {
		native.Select(ctx.Key("profile-managed-subscription"), &selected, options).Label("第一跳订阅").FillWidth().OnChange(func() { c.ChooseManagedSubscription(ids[selected]) })
	})
	nodeSelected, nodeOptions, nodeIDs := "请选择节点（待检查）", []string{}, map[string]string{}
	for i, n := range c.SubscriptionNodes[c.ProfileDraft.ManagedSubscriptionID] {
		if !n.Supported {
			continue
		}
		label := fmt.Sprintf("%d · %s · %s", i+1, n.Name, n.Type)
		if n.SkipsTLSVerification {
			label += " · 跳过节点证书验证"
		}
		nodeOptions = append(nodeOptions, label)
		nodeIDs[label] = n.ID
		if n.ID == c.ProfileDraft.ManagedNodeID {
			nodeSelected = label
		}
	}
	native.Field(ctx, "第一跳节点", func() {
		native.Select(ctx.Key("profile-managed-node"), &nodeSelected, nodeOptions).Label("第一跳节点").FillWidth().OnChange(func() { c.ChooseManagedNode(nodeIDs[nodeSelected]) })
	})
	if c.ProfileDraft.ManagedNodeID != "" && !c.managedNodeAvailable(c.ProfileDraft.ManagedSubscriptionID, c.ProfileDraft.ManagedNodeID) {
		native.Text(ctx, "原节点已移除或超出 ExitGuard 的当前能力，请明确重新选择；不会替换为其他节点。").FontSize(11).TextColor(t.Warning)
	}
	native.Text(ctx, "订阅节点是第一跳，由 ExitGuard 独立管理；保存和选择不会启动内核，检查出口时才会启动核验。").FontSize(11).TextColor(t.TextMuted)
}

func (c *Controller) profileOverviewChoice(ctx *native.Context) {
	labels := make([]string, 0, len(c.Profiles))
	ids := make(map[string]string, len(c.Profiles))
	selected := "选择已保存代理"
	for i, p := range c.Profiles {
		label := fmt.Sprintf("%d · %s · %s", i+1, p.Name, p.ProxyURL)
		labels = append(labels, label)
		ids[label] = p.ID
		if p.ID == c.OverviewProfileID {
			selected = label
		}
	}
	native.Column(ctx.Key("overview-profiles")).Gap(8).Children(func() {
		native.Text(ctx, "更换已保存代理").Bold()
		native.Field(ctx, "选择已保存代理", func() {
			native.Select(ctx.Key("overview-profile-choice"), &selected, labels).Label("选择已保存代理").Disabled(c.Busy).OnChange(func() { c.OverviewProfileID = ids[selected] })
		})
		native.Button(ctx.Key("overview-profile-use"), "使用所选代理").Disabled(c.Busy || !c.canUseProfile() || c.OverviewProfileID == "" || !c.savedProfileNodeAvailable(c.OverviewProfileID)).OnClick(func() { c.UseProfile(c.OverviewProfileID) })
		native.Text(ctx, "选择不会切换连接；明确使用后保持关闭，需要重新检查并手动启动。").FontSize(12).TextColor(ctx.Theme().TextMuted)
	})
}
