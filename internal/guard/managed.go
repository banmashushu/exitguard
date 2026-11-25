package guard

import (
	"context"
	"errors"
	"net"
	"sync"

	"exitguard/internal/managedproxy"
	"exitguard/internal/model"
	"exitguard/internal/subscription"
)

type managedLease interface {
	Settings() (string, string, string, string)
	Valid() bool
	Done() <-chan struct{}
	Stop() error
	Revoke()
}
type managedController interface {
	Ensure(context.Context, subscription.Node) (managedLease, error)
	Current(string) (managedLease, error)
	CoreIdentity() string
}
type ownedManagedController struct{ manager *managedproxy.Manager }
type ownedManagedLease struct{ *managedproxy.Lease }

func (l ownedManagedLease) Settings() (string, string, string, string) {
	return l.URL, l.Username, l.Password, l.Identity
}
func defaultManagedController(path string) managedController {
	return &ownedManagedController{manager: managedproxy.NewManager(managedproxy.DefaultOptions(path))}
}
func defaultSubscriptionURIConverter(path string) subscription.URIConverter {
	return managedproxy.NativeURIConverter(managedproxy.DefaultOptions(path))
}
func (c *ownedManagedController) Ensure(ctx context.Context, n subscription.Node) (managedLease, error) {
	l, e := c.manager.Ensure(ctx, managedproxy.Node{Identity: n.ID, Config: n.Config})
	if e != nil {
		return nil, e
	}
	return ownedManagedLease{l}, nil
}
func (c *ownedManagedController) Current(id string) (managedLease, error) {
	l, e := c.manager.Current(id)
	if e != nil {
		return nil, e
	}
	return ownedManagedLease{l}, nil
}
func (c *ownedManagedController) CoreIdentity() string { return c.manager.CoreIdentity() }
func (s *Service) detachManagedLocked() managedLease {
	l := s.managedLease
	s.managedLease = nil
	if l != nil {
		l.Revoke()
	}
	return l
}
func (s *Service) stopManagedLocked() {
	if l := s.detachManagedLocked(); l != nil {
		go func() { _ = l.Stop() }()
	}
}

type managedRoute struct {
	route
	lease       managedLease
	identity    string
	watchDone   chan struct{}
	watchExited chan struct{}
	closeOnce   sync.Once
}

func (r *managedRoute) Close() error {
	r.closeOnce.Do(func() { close(r.watchDone) })
	return r.route.Close()
}
func (r *managedRoute) Fingerprint(ctx context.Context) (string, error) {
	if !r.lease.Valid() {
		return "", &managedError{kind: managedUnavailable}
	}
	fp, e := r.route.Fingerprint(ctx)
	if e != nil {
		return "", e
	}
	return fp + "|managed:" + r.identity, nil
}
func (r *managedRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !r.lease.Valid() {
		return nil, &managedError{kind: managedUnavailable}
	}
	return r.route.DialContext(ctx, network, address)
}
func (r *managedRoute) Probe(ctx context.Context, raw string) (string, error) {
	if !r.lease.Valid() {
		return "", &managedError{kind: managedUnavailable}
	}
	return r.route.Probe(ctx, raw)
}
func (s *Service) managedRouteFor(ctx context.Context, c model.Config, user, password string, manual bool) (route, error) {
	s.mu.Lock()
	owned := s.running && s.listener != nil && s.boundPort == c.ProxyPort
	g := s.generation
	s.mu.Unlock()
	if !owned {
		return nil, errors.New("专属订阅核心需要守护服务独占当前监听端口")
	}
	lib, e := s.readSubscriptions()
	if e != nil {
		return nil, e
	}
	node, e := lib.Node(c.ManagedSubscriptionID, c.ManagedNodeID)
	if e != nil {
		return nil, e
	}
	var lease managedLease
	if manual {
		lease, e = s.managed.Ensure(ctx, node)
	} else {
		lease, e = s.managed.Current(node.ID)
	}
	if e != nil || lease == nil || !lease.Valid() {
		return nil, safeManagedError(e)
	}
	endpoint, frontUser, frontPassword, identity := lease.Settings()
	if identity == "" || ctx.Err() != nil {
		if manual {
			_ = lease.Stop()
		}
		return nil, errors.New("专属订阅核心启动已取消")
	}
	effective := copyConfig(c)
	effective.ManagedSubscriptionID, effective.ManagedNodeID = "", ""
	effective.PreProxyURL = endpoint
	r, e := s.makeChainedRemoteRoute(ctx, effective, user, password, frontUser, frontPassword)
	if e != nil {
		if manual {
			_ = lease.Stop()
		}
		return nil, e
	}
	s.mu.Lock()
	if s.generation != g || ctx.Err() != nil {
		s.mu.Unlock()
		r.Close()
		if manual {
			_ = lease.Stop()
		}
		return nil, errors.New("订阅路线验证已取消")
	}
	s.managedLease = lease
	s.mu.Unlock()
	result := &managedRoute{route: r, lease: lease, identity: identity, watchDone: make(chan struct{}), watchExited: make(chan struct{})}
	go func() {
		defer close(result.watchExited)
		select {
		case <-lease.Done():
		case <-result.watchDone:
			return
		}
		select {
		case <-result.watchDone:
			return
		default:
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		select {
		case <-result.watchDone:
			return
		default:
		}
		if s.generation == g && s.managedLease == lease {
			s.closeLocked()
			s.managedLease = nil
			s.status.State = "blocked"
			s.status.Reason = "专属订阅核心已退出，入口已关闭；请手动重新检查"
			s.status.ObservedIP = ""
			s.eventLocked(s.status.Reason)
		}
	}()
	return result, nil
}

type managedFailureKind uint8

const (
	managedUnavailable managedFailureKind = iota
	managedPackage
	managedNode
	managedStart
	managedReadiness
	managedStorage
)

type managedError struct{ kind managedFailureKind }

func (e *managedError) Error() string {
	switch e.kind {
	case managedPackage:
		return "专属代理核心缺失或校验失败，请重新安装完整安装包"
	case managedNode:
		return "所选订阅节点地址或配置不符合要求，请重新选择有效节点"
	case managedStart:
		return "专属核心未能启动，请暂停后手动重新检查"
	case managedReadiness:
		return "专属核心未就绪，请暂停后手动重新检查"
	case managedStorage:
		return "专属核心私有目录不可用，请检查本机文件权限"
	default:
		return "专属订阅核心已停止，请手动重新检查；自动恢复不会重新启动核心"
	}
}
func safeManagedError(source error) *managedError {
	kind := managedUnavailable
	switch {
	case errors.Is(source, managedproxy.ErrPackage):
		kind = managedPackage
	case errors.Is(source, managedproxy.ErrNode):
		kind = managedNode
	case errors.Is(source, managedproxy.ErrStart):
		kind = managedStart
	case errors.Is(source, managedproxy.ErrReadiness):
		kind = managedReadiness
	case errors.Is(source, managedproxy.ErrStorage):
		kind = managedStorage
	}
	return &managedError{kind: kind}
}
