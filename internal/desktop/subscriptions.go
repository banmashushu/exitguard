package desktop

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"exitguard/internal/model"
	"exitguard/internal/subscription"
)

// SubscriptionDraft is private editing state. Stored URLs are never read back
// from the library, and source content is held only by the submitting worker.
type SubscriptionDraft struct {
	ID, Name, SourceKind, URL, FilePath string
	DownloadRoute                       string
}

const maxSubscriptionFileBytes = 5 << 20

type subscriptionCatalog struct {
	summaries []model.SubscriptionSummary
	nodes     map[string][]model.SubscriptionNode
}

func (c *Controller) readSubscriptionCatalog() (subscriptionCatalog, error) {
	summaries, err := c.core.Subscriptions()
	if err != nil {
		return subscriptionCatalog{}, errors.New("无法读取本机订阅列表；请检查订阅文件后重试")
	}
	catalog := subscriptionCatalog{summaries: summaries, nodes: make(map[string][]model.SubscriptionNode, len(summaries))}
	for _, s := range summaries {
		nodes, err := c.core.SubscriptionNodes(s.ID)
		if err != nil {
			return subscriptionCatalog{}, errors.New("无法读取订阅节点；原列表保留，请重试")
		}
		catalog.nodes[s.ID] = nodes
	}
	return catalog, nil
}

func (c *Controller) applySubscriptionCatalog(catalog subscriptionCatalog) {
	c.Subscriptions, c.SubscriptionNodes, c.SubscriptionsLoaded = catalog.summaries, catalog.nodes, true
	if _, ok := c.subscription(c.ViewedSubscriptionID); !ok {
		c.ViewedSubscriptionID = ""
	}
	if !c.Dirty {
		c.Draft = draftFrom(c.Config)
	}
}

func (c *Controller) OpenSubscriptions() {
	c.Page = "订阅管理"
	if !c.SubscriptionsLoaded {
		c.LoadSubscriptions()
	}
}

// Loading public metadata is explicit. Refresh/status polling never reads the
// subscription library and never downloads a source.
func (c *Controller) LoadSubscriptions() {
	c.begin(func(context.Context) (func(), error) {
		catalog, err := c.readSubscriptionCatalog()
		return func() { c.applySubscriptionCatalog(catalog) }, err
	}, "已载入本机订阅和节点；未选择或启动任何节点")
}

func (c *Controller) MarkSubscriptionDirty() { c.subscriptionRevision++ }

func readSubscriptionFile(ctx context.Context, path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("请填写要导入的本机文件完整路径")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSubscriptionFileBytes {
		return nil, errors.New("订阅文件须为不超过 5 MiB 的普通文件")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("无法读取所选本机订阅文件；请检查路径和权限")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSubscriptionFileBytes {
		return nil, errors.New("订阅文件须为不超过 5 MiB 的普通文件")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(f, maxSubscriptionFileBytes+1))
	if err != nil || len(content) > maxSubscriptionFileBytes {
		return nil, errors.New("订阅文件读取失败或超过 5 MiB；未导入")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

func (c *Controller) ImportSubscription() {
	if c.Busy || c.closed {
		return
	}
	draft := c.SubscriptionDraft
	name := strings.TrimSpace(draft.Name)
	if name == "" {
		c.Notice = "请填写订阅名称"
		return
	}
	input := model.SubscriptionInput{ID: draft.ID, Name: name, DownloadRoute: "direct"}
	switch draft.SourceKind {
	case "url":
		if draft.DownloadRoute == "active_exitguard" {
			input.DownloadRoute = "active_exitguard"
		} else if draft.DownloadRoute != "" && draft.DownloadRoute != "direct" {
			c.Notice = "请选择订阅下载路径"
			return
		}
		input.URL = strings.TrimSpace(draft.URL)
		if input.URL == "" {
			c.Notice = "请填写私密 HTTPS 订阅链接"
			return
		}
	case "file":
		if strings.TrimSpace(draft.FilePath) == "" {
			c.Notice = "请填写明确选择的本机订阅文件完整路径"
			return
		}
	default:
		c.Notice = "请选择订阅导入方式"
		return
	}
	revision := c.subscriptionRevision
	c.SubscriptionDraft.URL, c.SubscriptionDraft.FilePath = "", ""
	c.beginSettled(func(ctx context.Context) (func(), func(), error) {
		if draft.SourceKind == "file" {
			content, err := readSubscriptionFile(ctx, strings.TrimSpace(draft.FilePath))
			if err != nil {
				return nil, nil, err
			}
			input.Content = content
		}
		_, err := c.core.ImportSubscription(ctx, input)
		if err != nil {
			return nil, nil, subscriptionActionFailure(err, "订阅导入失败；原订阅保持不变，来源输入已清空。请核对内容，或改用本机文件导入")
		}
		catalog, err := c.readSubscriptionCatalog()
		return nil, func() {
			c.applySubscriptionCatalog(catalog)
			if c.subscriptionRevision == revision {
				c.SubscriptionDraft = SubscriptionDraft{SourceKind: draft.SourceKind, DownloadRoute: "direct"}
			}
		}, err
	}, "订阅已保存到此设备；请到代理设置明确选择节点作为第一跳，原固定出口和期望 IP 保持原配置")
}

func (c *Controller) RefreshSubscription(id string) {
	c.refreshSubscription(id, false)
}

func (c *Controller) RefreshSubscriptionViaActive(id string) {
	c.refreshSubscription(id, true)
}

func (c *Controller) refreshSubscription(id string, viaActive bool) {
	if c.Busy || c.closed {
		return
	}
	s, ok := c.subscription(id)
	if !ok || s.SourceKind != "url" {
		c.Notice = "本机文件订阅请重新导入文件；仅链接订阅可下载更新"
		return
	}
	success := "订阅已直接更新。请在代理设置选择第一跳节点，再检查出口。"
	route := subscription.DownloadDirect
	if viaActive {
		success = "已通过当前出口更新并记住下载路径。使用此订阅的连接需重新检查并手动启动；原节点失效时请重新选择。"
		route = subscription.DownloadActiveExitGuard
	}
	c.Notice = "正在更新订阅 · " + subscriptionDownloadRouteLabel(route)
	c.beginSettled(func(ctx context.Context) (func(), func(), error) {
		var err error
		if viaActive {
			_, err = c.core.RefreshSubscriptionViaActive(ctx, id)
		} else {
			_, err = c.core.RefreshSubscriptionDirect(ctx, id)
		}
		if err != nil {
			fallback := "订阅更新失败；原订阅与节点保留，请稍后重试或导入本机文件"
			if viaActive {
				fallback = "通过当前出口更新失败；请先检查并启动出口。原订阅保留，不会改用直接下载"
			}
			return nil, nil, subscriptionActionFailure(err, fallback)
		}
		catalog, err := c.readSubscriptionCatalog()
		return nil, func() { c.applySubscriptionCatalog(catalog) }, err
	}, success)
}

func (c *Controller) subscription(id string) (model.SubscriptionSummary, bool) {
	for _, s := range c.Subscriptions {
		if s.ID == id {
			return s, true
		}
	}
	return model.SubscriptionSummary{}, false
}
func (c *Controller) ViewSubscription(id string) {
	if c.Busy || c.closed {
		return
	}
	if _, ok := c.subscription(id); ok {
		c.ViewedSubscriptionID = id
	}
}
func (c *Controller) RequestDeleteSubscription(id string) {
	if c.Busy || c.closed {
		return
	}
	if _, ok := c.subscription(id); ok {
		c.DeleteSubscriptionID = id
	}
}
func (c *Controller) ConfirmDeleteSubscription() {
	if c.Busy || c.closed || c.DeleteSubscriptionID == "" {
		return
	}
	id := c.DeleteSubscriptionID
	c.beginSettled(func(context.Context) (func(), func(), error) {
		if err := c.core.DeleteSubscription(id); err != nil {
			return nil, nil, errors.New("订阅未能删除；请先在代理配置中移除对此订阅的引用，再检查本机文件权限并重试")
		}
		catalog, err := c.readSubscriptionCatalog()
		return nil, func() { c.applySubscriptionCatalog(catalog); c.DeleteSubscriptionID = "" }, err
	}, "订阅已从此设备删除")
}
func (c *Controller) managedNodeAvailable(subscriptionID, nodeID string) bool {
	if !c.SubscriptionsLoaded {
		return false
	}
	for _, n := range c.SubscriptionNodes[subscriptionID] {
		if n.ID == nodeID && n.Supported {
			return true
		}
	}
	return false
}
func (c *Controller) ChooseManagedSubscription(id string) {
	if _, ok := c.subscription(id); !ok {
		return
	}
	c.ProfileDraft.ManagedSubscriptionID, c.ProfileDraft.ManagedNodeID = id, ""
	c.MarkProfileDirty()
}
func (c *Controller) ChooseManagedNode(id string) {
	if !c.managedNodeAvailable(c.ProfileDraft.ManagedSubscriptionID, id) {
		return
	}
	c.ProfileDraft.ManagedNodeID = id
	c.MarkProfileDirty()
}

func subscriptionActionFailure(source error, fallback string) error {
	if safe := subscription.ResponseFailure(source); safe != nil {
		return errors.New(safe.Error() + "；原订阅与节点保留")
	}
	return errors.New(fallback)
}
