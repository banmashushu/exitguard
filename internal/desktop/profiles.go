package desktop

import (
	"context"
	"errors"
	"net"
	"strings"

	"exitguard/internal/model"
)

// ProfileDraft is local editing state. Only the submitted immutable input crosses
// into a worker. Public profile snapshots never refill either account field.
type ProfileDraft struct {
	ID, Name, Protocol, Host, Port, ExpectedIPs string
	Username, Password                          string
	HasCredentials, ClearCredentials            bool
	originalURL                                 string
}

func blankProfileDraft() ProfileDraft { return ProfileDraft{Protocol: "HTTPS", Port: "443"} }

func profileDraftFrom(p model.RemoteProfile) ProfileDraft {
	d := ProfileDraft{ID: p.ID, Name: p.Name, ExpectedIPs: strings.Join(p.ExpectedIPs, ", "), HasCredentials: p.HasCredentials, originalURL: p.ProxyURL}
	d.Protocol, d.Host, d.Port, _ = splitProfileEndpoint(p.ProxyURL)
	return d
}

func (d ProfileDraft) input() (model.RemoteProfileInput, error) {
	name := strings.TrimSpace(d.Name)
	if name == "" {
		return model.RemoteProfileInput{}, errors.New("请填写代理名称，方便区分每个独立代理")
	}
	endpoint, err := profileEndpoint(d.Protocol, d.Host, d.Port)
	if err != nil {
		return model.RemoteProfileInput{}, err
	}
	ips := splitLines(d.ExpectedIPs)
	for _, raw := range ips {
		if ip := net.ParseIP(raw); ip == nil || ip.To4() == nil {
			return model.RemoteProfileInput{}, errors.New("期望出口请填写有效公网 IPv4；也可以先留空，使用此代理后测试候选 IP")
		}
	}
	action := "keep"
	if d.ClearCredentials {
		if d.Username != "" || d.Password != "" {
			return model.RemoteProfileInput{}, errors.New("清除账户与填写新账户只能选择一种；请清空新账户或取消清除")
		}
		action = "clear"
	} else if d.Username != "" || d.Password != "" {
		if d.Username == "" || d.Password == "" {
			return model.RemoteProfileInput{}, errors.New("新用户名和密码需要成对填写；都留空会保留已保存账户")
		}
		action = "replace"
	}
	if d.HasCredentials && endpoint != d.originalURL && action == "keep" {
		return model.RemoteProfileInput{}, errors.New("已保存账户绑定原服务器；更换地址后请填写一对新账户，或明确勾选清除已保存账户")
	}
	return model.RemoteProfileInput{ID: d.ID, Name: name, ProxyURL: endpoint, ExpectedIPs: ips, CredentialAction: action, Username: d.Username, Password: d.Password}, nil
}

func (c *Controller) InitializeProfiles() {
	c.Refresh()
	c.initializeProfileDraft()
}

func (c *Controller) completeProfileInitialization(profiles []model.RemoteProfile) {
	c.refreshCurrentState()
	c.Profiles, c.ProfileError = profiles, ""
	c.initializeProfileDraft()
}

func (c *Controller) initializeProfileDraft() {
	if !c.Dirty {
		// Migration may detach a legacy route after this controller first read
		// it. A clean advanced form must reflect that completed transition.
		c.Draft = draftFrom(c.Config)
	} else {
		// An unrelated edit, such as DNS, must not keep an obsolete legacy
		// route alive. Compare against the original startup snapshot so a
		// status refresh during migration cannot disguise untouched fields
		// as user edits. Explicitly edited fields keep their draft values.
		current := draftFrom(c.Config)
		if c.Draft.ProxyURL == c.startupDraftBase.ProxyURL {
			c.Draft.ProxyURL = current.ProxyURL
		}
		if c.Draft.ExpectedIPs == c.startupDraftBase.ExpectedIPs {
			c.Draft.ExpectedIPs = current.ExpectedIPs
		}
	}
	if c.OverviewProfileID == "" {
		c.OverviewProfileID = c.Config.RemoteProfileID
	}
	if c.ProfileDirty {
		return
	}
	for _, p := range c.Profiles {
		if p.ID == c.Config.RemoteProfileID {
			c.loadProfile(p)
			return
		}
	}
}

func (c *Controller) MarkProfileDirty() {
	c.ProfileDirty = true
	c.profileRevision++
	c.DeleteProfileID = ""
}

func (c *Controller) profile(id string) (model.RemoteProfile, bool) {
	for _, p := range c.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return model.RemoteProfile{}, false
}

func (c *Controller) loadProfile(p model.RemoteProfile) {
	c.ProfileDraft = profileDraftFrom(p)
	c.ProfileDirty = false
	c.profileRevision++
	c.PendingProfileAction, c.PendingProfileID, c.DeleteProfileID = "", "", ""
}

func (c *Controller) NewProfile()           { c.requestProfileChange("new", "") }
func (c *Controller) EditProfile(id string) { c.requestProfileChange("edit", id) }
func (c *Controller) requestProfileChange(action, id string) {
	if c.Busy || c.closed || c.ProfileError != "" {
		return
	}
	if action == "edit" && id == c.ProfileDraft.ID {
		return
	}
	if c.ProfileDirty {
		c.PendingProfileAction, c.PendingProfileID = action, id
		c.DeleteProfileID = ""
		return
	}
	c.changeProfile(action, id)
}
func (c *Controller) changeProfile(action, id string) {
	if action == "new" {
		c.ProfileDraft = blankProfileDraft()
		c.ProfileDirty = false
		c.profileRevision++
		c.PendingProfileAction, c.PendingProfileID, c.DeleteProfileID = "", "", ""
		return
	}
	if p, ok := c.profile(id); ok {
		c.loadProfile(p)
	}
}
func (c *Controller) CancelProfileChange() { c.PendingProfileAction, c.PendingProfileID = "", "" }
func (c *Controller) DiscardProfileChanges() {
	if c.Busy || c.closed {
		return
	}
	action, id := c.PendingProfileAction, c.PendingProfileID
	if action != "" {
		c.changeProfile(action, id)
	}
}
func (c *Controller) RevertProfile() {
	if c.ProfileDraft.ID == "" {
		c.PendingProfileAction, c.PendingProfileID = "new", ""
	} else {
		c.PendingProfileAction, c.PendingProfileID = "edit", c.ProfileDraft.ID
	}
}

func (c *Controller) SaveProfile() {
	if c.Busy || c.closed || c.ProfileError != "" {
		return
	}
	input, err := c.ProfileDraft.input()
	if err != nil {
		c.Notice = err.Error()
		return
	}
	revision := c.profileRevision
	c.ProfileDraft.Username, c.ProfileDraft.Password = "", ""
	c.beginSettled(func(context.Context) (func(), func(), error) {
		saved, err := c.core.SaveRemoteProfile(input)
		if err != nil {
			return nil, nil, errors.New("代理保存失败；账户输入已清空，请核对填写内容与本机配置文件后重试")
		}
		return nil, func() {
			if c.profileRevision == revision {
				c.loadProfile(saved)
			} else {
				// Edits made while the first save runs still belong to this new record.
				c.ProfileDraft.ID = saved.ID
				c.ProfileDraft.HasCredentials = saved.HasCredentials
				c.ProfileDraft.originalURL = saved.ProxyURL
			}
			if !c.Dirty {
				c.Draft = draftFrom(c.Config)
			}
		}, nil
	}, "代理已保存到此设备；使用此代理后检查出口，再手动启动。保存当前使用的代理会暂停连接。")
}

func (c *Controller) UseProfile(id string) {
	if !c.canUseProfile() {
		c.Notice = "请先保存或放弃代理修改及高级设置，再使用已保存代理"
		return
	}
	if _, ok := c.profile(id); !ok {
		c.Notice = "请先选择一个已保存代理"
		return
	}
	revision := c.draftRevision
	c.beginSettled(func(context.Context) (func(), func(), error) {
		err := c.core.SelectRemoteProfile(id)
		return nil, func() {
			c.OverviewProfileID = id
			c.Candidate = ""
			if revision == c.draftRevision {
				c.Draft = draftFrom(c.Config)
				c.Dirty = false
			}
		}, err
	}, "已使用所选代理，连接保持关闭；请检查出口，再手动启动。")
}

func (c *Controller) canUseProfile() bool {
	if c.ProfileDirty || c.ProfileError != "" {
		return false
	}
	if !c.Dirty {
		return true
	}
	// Explicit Use already changes the source to remote. It can resolve this
	// source-only draft without overwriting any other unsaved global setting.
	draft := c.Draft
	if draft.Mode != "remote" {
		return false
	}
	draft.Mode = c.Config.Mode
	return draft == draftFrom(c.Config)
}

func (c *Controller) RequestDeleteProfile(id string) {
	if c.Busy || c.closed {
		return
	}
	if _, ok := c.profile(id); !ok {
		return
	}
	c.DeleteProfileID = id
	c.PendingProfileAction, c.PendingProfileID = "", ""
}
func (c *Controller) CancelDeleteProfile() { c.DeleteProfileID = "" }
func (c *Controller) ConfirmDeleteProfile() {
	if c.Busy || c.closed || c.DeleteProfileID == "" {
		return
	}
	id := c.DeleteProfileID
	revision := c.profileRevision
	c.beginSettled(func(context.Context) (func(), func(), error) {
		err := c.core.DeleteRemoteProfile(id)
		return nil, func() {
			c.DeleteProfileID = ""
			if c.ProfileDraft.ID == id {
				if c.profileRevision == revision {
					c.changeProfile("new", "")
				} else {
					// The deleted record no longer owns edits entered after the
					// confirmation. Keep those as a fresh unsaved profile.
					c.ProfileDraft.ID, c.ProfileDraft.originalURL = "", ""
					c.ProfileDraft.HasCredentials, c.ProfileDraft.ClearCredentials = false, false
				}
			}
			if c.OverviewProfileID == id {
				c.OverviewProfileID = c.Config.RemoteProfileID
			}
			if !c.Dirty {
				c.Draft = draftFrom(c.Config)
			}
		}, err
	}, "代理已删除；如删除的是当前代理，连接保持关闭。")
}

func (c *Controller) activeProfileName() string {
	if p, ok := c.profile(c.Config.RemoteProfileID); ok {
		return p.Name
	}
	if c.Config.Mode == "remote" {
		return "尚未使用已保存代理"
	}
	return sourceLabels[c.Config.Mode]
}
