package guard

import (
	"context"
	"errors"
	"io"
	"os"

	"exitguard/internal/model"
	"exitguard/internal/subscription"
)

func (s *Service) readSubscriptions() (subscription.Library, error) {
	empty := subscription.Empty()
	if !credentialPersistenceSupported {
		return empty, subscription.ErrStorage
	}
	f, e := openCredentialRecord(s.configPath + ".subscriptions.json")
	if os.IsNotExist(e) {
		return empty, nil
	}
	if e != nil {
		return empty, subscription.ErrStorage
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() > subscription.MaxBytes {
		return empty, subscription.ErrStorage
	}
	data, e := io.ReadAll(io.LimitReader(f, subscription.MaxBytes+1))
	if e != nil || len(data) > subscription.MaxBytes {
		return empty, subscription.ErrStorage
	}
	return subscription.Decode(data)
}
func (s *Service) writeSubscriptions(lib subscription.Library) error {
	data, e := subscription.Encode(lib)
	if e != nil || writeCredentialFile(s.configPath+".subscriptions.json", data) != nil {
		return subscription.ErrStorage
	}
	return nil
}
func (s *Service) Subscriptions() ([]model.SubscriptionSummary, error) {
	s.subscriptionMu.Lock()
	defer s.subscriptionMu.Unlock()
	lib, e := s.readSubscriptions()
	if e != nil {
		return nil, e
	}
	return lib.Summaries(), nil
}
func (s *Service) SubscriptionNodes(id string) ([]model.SubscriptionNode, error) {
	s.subscriptionMu.Lock()
	defer s.subscriptionMu.Unlock()
	lib, e := s.readSubscriptions()
	if e != nil {
		return nil, e
	}
	r, e := lib.Record(id)
	if e != nil {
		return nil, e
	}
	return subscription.PublicNodes(r.Nodes), nil
}
func (s *Service) ImportSubscription(ctx context.Context, input model.SubscriptionInput) (model.SubscriptionSummary, error) {
	s.subscriptionMu.Lock()
	defer s.subscriptionMu.Unlock()
	return s.importSubscription(ctx, input)
}
func (s *Service) importSubscription(ctx context.Context, input model.SubscriptionInput) (model.SubscriptionSummary, error) {
	lib, e := s.readSubscriptions()
	if e != nil {
		return model.SubscriptionSummary{}, e
	}
	fetch := s.fetchSubscription
	var capture *sourceDownloadCapture
	if input.URL != "" {
		route, e := subscription.NormalizeDownloadRoute(input.DownloadRoute)
		if e != nil {
			return model.SubscriptionSummary{}, e
		}
		input.DownloadRoute = route
		if route == subscription.DownloadActiveExitGuard {
			capture, e = s.captureSourceDownload(ctx)
			if e != nil {
				return model.SubscriptionSummary{}, e
			}
			defer capture.release()
			ctx = capture.ctx
			fetch = s.fetchOnCapturedRoute(capture)
		}
	} else {
		input.DownloadRoute = subscription.DownloadDirect
	}
	candidate, e := lib.PrepareWithURIConverter(ctx, input, fetch, s.convertSubscriptionURI)
	if e != nil {
		return model.SubscriptionSummary{}, e
	}
	if e = lib.Put(candidate); e != nil {
		return model.SubscriptionSummary{}, e
	}
	if _, e = subscription.Encode(lib); e != nil {
		return model.SubscriptionSummary{}, e
	}
	if capture != nil {
		if e = capture.check(); e != nil {
			return model.SubscriptionSummary{}, e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return model.SubscriptionSummary{}, errors.New("订阅操作已取消")
	}
	if capture != nil && !capture.currentLocked() {
		return model.SubscriptionSummary{}, subscription.ErrActiveRouteUnavailable
	}
	// Verify generation/pointer/fingerprint/context and persist in one service
	// critical section. A concurrent Pause either wins first (no write), or runs
	// after this candidate has committed. Process waiting stays outside this lock.
	if capture != nil {
		capture.detachLocked()
	}
	if s.config.ManagedSubscriptionID == candidate.ID {
		s.closeLocked()
		s.stopManagedLocked()
		s.status.State = "unconfigured"
		s.status.Reason = "当前订阅已更新，连接已暂停；请核对原节点后重新检查并手动启动"
		s.status.ObservedIP = ""
		s.eventLocked(s.status.Reason)
	}
	if e = s.writeSubscriptions(lib); e != nil {
		return model.SubscriptionSummary{}, e
	}
	return candidate.Summary(), nil
}

func (s *Service) RefreshSubscription(ctx context.Context, id string) (model.SubscriptionSummary, error) {
	return s.refreshSubscription(ctx, id, "")
}

// RefreshSubscriptionDirect uses the saved URL independently of the fixed exit.
func (s *Service) RefreshSubscriptionDirect(ctx context.Context, id string) (model.SubscriptionSummary, error) {
	return s.refreshSubscription(ctx, id, subscription.DownloadDirect)
}

// RefreshSubscriptionViaActive explicitly selects the already verified route.
// Its preference is persisted only after the downloaded candidate is accepted.
func (s *Service) RefreshSubscriptionViaActive(ctx context.Context, id string) (model.SubscriptionSummary, error) {
	return s.refreshSubscription(ctx, id, subscription.DownloadActiveExitGuard)
}
func (s *Service) refreshSubscription(ctx context.Context, id, route string) (model.SubscriptionSummary, error) {
	s.subscriptionMu.Lock()
	defer s.subscriptionMu.Unlock()
	lib, e := s.readSubscriptions()
	if e != nil {
		return model.SubscriptionSummary{}, e
	}
	r, e := lib.Record(id)
	if e != nil {
		return model.SubscriptionSummary{}, e
	}
	if r.SourceKind != "url" {
		return model.SubscriptionSummary{}, errors.New("文件订阅请重新选择文件导入")
	}
	if route == "" {
		route = r.DownloadRoute
	}
	return s.importSubscription(ctx, model.SubscriptionInput{ID: id, Name: r.Name, URL: r.SourceURL, DownloadRoute: route})
}

func (s *Service) DeleteSubscription(id string) error {
	s.subscriptionMu.Lock()
	defer s.subscriptionMu.Unlock()
	s.mu.Lock()
	profiles, e := s.profilesLocked()
	s.mu.Unlock()
	if e != nil {
		return e
	}
	for _, p := range profiles.Profiles {
		if p.ManagedSubscriptionID == id {
			return errors.New("请先在所有代理配置中取消引用此订阅，再删除")
		}
	}
	lib, e := s.readSubscriptions()
	if e != nil {
		return e
	}
	if e = lib.Delete(id); e != nil {
		return e
	}
	return s.writeSubscriptions(lib)
}
