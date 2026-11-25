package guard

import (
	"context"
	"net"
	"sync"

	"exitguard/internal/subscription"
)

// sourceDownloadCapture owns only this operation and its sockets, never the
// active route lifetime. Closing the service generation cancels its in-flight
// dial immediately; a source error cannot start a route or choose another one.
type sourceDownloadCapture struct {
	service                 *Service
	ctx                     context.Context
	cancel                  context.CancelFunc
	id, generation          uint64
	route                   route
	fingerprint, verifiedIP string
}

func (s *Service) captureSourceDownload(ctx context.Context) (*sourceDownloadCapture, error) {
	operation, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if operation.Err() != nil || !activeState(s.status.State) || !s.running || s.listener == nil || s.boundPort != s.config.ProxyPort || s.activeRoute == nil || s.fingerprint == "" || !expected(s.config, s.status.ObservedIP) {
		s.mu.Unlock()
		cancel()
		return nil, subscription.ErrActiveRouteUnavailable
	}
	s.sourceOperationID++
	captured := &sourceDownloadCapture{service: s, ctx: operation, cancel: cancel, id: s.sourceOperationID, generation: s.generation, route: s.activeRoute, fingerprint: s.fingerprint, verifiedIP: s.status.ObservedIP}
	if s.sourceCancels == nil {
		s.sourceCancels = make(map[uint64]context.CancelFunc)
	}
	s.sourceCancels[captured.id] = cancel
	s.mu.Unlock()
	if e := captured.check(); e != nil {
		captured.release()
		return nil, e
	}
	return captured, nil
}
func (c *sourceDownloadCapture) currentLocked() bool {
	s := c.service
	return c.ctx.Err() == nil && s.generation == c.generation && s.activeRoute == c.route && s.fingerprint == c.fingerprint && s.status.ObservedIP == c.verifiedIP && activeState(s.status.State) && s.running && s.listener != nil && s.boundPort == s.config.ProxyPort
}
func (c *sourceDownloadCapture) check() error {
	s := c.service
	s.mu.Lock()
	current := c.currentLocked()
	s.mu.Unlock()
	if !current {
		return subscription.ErrActiveRouteUnavailable
	}
	fp, e := c.route.Fingerprint(c.ctx)
	if e != nil || fp != c.fingerprint {
		return subscription.ErrActiveRouteUnavailable
	}
	s.mu.Lock()
	current = c.currentLocked()
	s.mu.Unlock()
	if !current {
		return subscription.ErrActiveRouteUnavailable
	}
	return nil
}
func (c *sourceDownloadCapture) release() {
	c.service.mu.Lock()
	delete(c.service.sourceCancels, c.id)
	c.service.mu.Unlock()
	c.cancel()
}

// detachLocked is the commit point: a successful update may intentionally close
// the very managed route used to download it. Future Pause cancels other work.
func (c *sourceDownloadCapture) detachLocked() { delete(c.service.sourceCancels, c.id) }
func (c *sourceDownloadCapture) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if e := c.check(); e != nil {
		return nil, e
	}
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	connection, e := c.route.DialContext(dialCtx, network, address)
	if e != nil {
		if c.check() != nil {
			return nil, subscription.ErrActiveRouteUnavailable
		}
		return nil, e
	}
	if e = c.check(); e != nil {
		connection.Close()
		return nil, e
	}
	if !c.service.track(connection, c.generation) {
		return nil, subscription.ErrActiveRouteUnavailable
	}
	// Store the underlying connection in Service.connections. closeLocked closes
	// it under mu; this wrapper's Close may unregister only outside that lock.
	owned := &sourceDownloadConn{Conn: connection, service: c.service}
	owned.mu.Lock()
	owned.stop = context.AfterFunc(c.ctx, func() { _ = owned.Close() })
	owned.mu.Unlock()
	return owned, nil
}

type sourceDownloadConn struct {
	net.Conn
	service *Service
	once    sync.Once
	mu      sync.Mutex
	stop    func() bool
}

func (c *sourceDownloadConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		stop := c.stop
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		c.service.untrack(c.Conn)
	})
	return nil
}
func (s *Service) fetchOnCapturedRoute(c *sourceDownloadCapture) subscription.Fetcher {
	return func(_ context.Context, raw string) ([]byte, error) {
		fetch := s.fetchSubscriptionThrough
		if fetch == nil {
			fetch = subscription.FetchThrough
		}
		content, e := fetch(c.ctx, raw, c.dial)
		if current := c.check(); current != nil {
			return nil, current
		}
		return content, e
	}
}
