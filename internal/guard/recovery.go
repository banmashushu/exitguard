package guard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"exitguard/internal/model"
)

var recoveryDelays = [...]time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}

var (
	errRecoveryPath = errors.New("原出口路径不一致，需手动重新检查")
	errRecoveryIP   = errors.New("公网 IP 与原会话不一致，需手动重新检查")
)

type recoverySnapshot struct {
	generation                  uint64
	config                      model.Config
	secret, username, password  string
	fingerprint, lastVerifiedIP string
	wait                        func(context.Context, time.Duration) error
	originCheckID               string
	attempt                     int
}

func waitRecovery(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func transientRecoveryFailure(e error) bool {
	failure := safeProbeError(e)
	switch failure.kind {
	case probeForwardFailure:
		return failure.forward != nil && failure.forward.transient()
	case probeTimeout, probeNetworkFailure, probeBodyRead, probeUpstreamUnavailable:
		return true
	case probeHTTPStatus:
		return failure.status == 429 || failure.status >= 500 && failure.status <= 599
	default:
		return false
	}
}

// Caller holds mu. Only an explicitly armed, currently active ordinary proxy
// may retain recovery intent across revocation of the old route and sockets.
func (s *Service) beginRecoveryLocked(g uint64, reason string, origin ...string) bool {
	if g != s.generation || !activeState(s.status.State) || !s.armedIntent || !s.config.AutoRecover || s.config.EnforcementMode != "proxy-only" || s.cancelRecovery != nil || s.runContext == nil || s.runContext.Err() != nil || !s.running || s.listener == nil || s.boundPort != s.config.ProxyPort {
		return false
	}
	ip, e := validProbeIP(s.status.ObservedIP)
	if e != nil || !expected(s.config, ip) || s.fingerprint == "" {
		return false
	}
	snapshot := recoverySnapshot{config: copyConfig(s.config), secret: s.secret, username: s.proxyUsername, password: s.proxyPassword, fingerprint: s.fingerprint, lastVerifiedIP: ip, wait: s.recoveryWait}
	if len(origin) != 0 {
		snapshot.originCheckID = origin[0]
	}
	s.closeLocked()
	snapshot.generation = s.generation
	s.armedIntent = true
	ctx, cancel := context.WithCancel(s.runContext)
	s.cancelRecovery = cancel
	s.status.State = "recovering"
	s.status.Reason = reason + "；转发已暂停，正在重新核验原出口"
	s.status.RecoveryAttempt, s.status.RecoveryMaxAttempts = 1, len(recoveryDelays)
	s.status.NextRetryAt = time.Now().Add(recoveryDelays[0]).UTC().Format(time.RFC3339)
	s.eventLocked(s.status.Reason)
	go s.recoverRoute(ctx, cancel, snapshot)
	return true
}

func (s *Service) recoveryCurrentLocked(ctx context.Context, snapshot recoverySnapshot) bool {
	return ctx.Err() == nil && s.generation == snapshot.generation && s.armedIntent && s.status.State == "recovering" && s.running && s.listener != nil && s.boundPort == snapshot.config.ProxyPort
}

func (s *Service) recoverRoute(ctx context.Context, cancel context.CancelFunc, snapshot recoverySnapshot) {
	defer cancel()
	// A cancelled dependency may take time to unwind. A subsequent episode waits
	// here rather than starting another retry validator or timer concurrently.
	select {
	case s.recoverySlot <- struct{}{}:
		defer func() { <-s.recoverySlot }()
	case <-ctx.Done():
		return
	}
	for attempt, delay := range recoveryDelays {
		s.mu.Lock()
		if !s.recoveryCurrentLocked(ctx, snapshot) {
			s.mu.Unlock()
			return
		}
		s.status.RecoveryAttempt = attempt + 1
		s.status.NextRetryAt = time.Now().Add(delay).UTC().Format(time.RFC3339)
		s.mu.Unlock()
		if e := snapshot.wait(ctx, delay); e != nil {
			return
		}
		s.mu.Lock()
		if !s.recoveryCurrentLocked(ctx, snapshot) {
			s.mu.Unlock()
			return
		}
		s.status.NextRetryAt = ""
		s.status.Reason = fmt.Sprintf("转发已暂停，正在第 %d/%d 次核验原出口", attempt+1, len(recoveryDelays))
		s.mu.Unlock()
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 15*time.Second)
		snapshot.attempt = attempt + 1
		attemptCtx = s.startProbeTrace(attemptCtx, diagnosticRecovery, snapshot.generation, snapshot.attempt, snapshot.originCheckID)
		candidate, ip, e := s.recoveryCandidate(attemptCtx, snapshot)
		attemptCancel()
		if e != nil {
			if ctx.Err() != nil {
				return
			}
			if transientRecoveryFailure(e) && attempt+1 < len(recoveryDelays) {
				continue
			}
			reason := "自动恢复已停止：" + safeProbeError(e).Error() + "，需手动重新检查"
			if errors.Is(e, errRecoveryPath) || errors.Is(e, errRecoveryIP) {
				reason = "自动恢复已停止：" + e.Error()
			} else if transientRecoveryFailure(e) {
				reason = "自动重试已用尽（3 次），入口保持关闭：" + safeProbeError(e).Error()
			}
			reason += probeTraceSuffix(attemptCtx, e)
			s.finishRecoveryBlocked(snapshot, reason, ip)
			return
		}
		s.mu.Lock()
		if !s.recoveryCurrentLocked(ctx, snapshot) {
			s.mu.Unlock()
			candidate.Close()
			return
		}
		s.activeRoute, s.fingerprint = candidate, snapshot.fingerprint
		s.cancelRecovery = nil
		s.status.State = "proxy_active"
		s.status.Reason = "原出口路径和公网 IP 已重新验证，代理转发已恢复；系统防绕行未验证"
		s.status.ObservedIP, s.status.CheckedAt = ip, time.Now().UTC().Format(time.RFC3339)
		s.status.RecoveryAttempt, s.status.RecoveryMaxAttempts, s.status.NextRetryAt = 0, 0, ""
		s.eventLocked(s.status.Reason)
		s.mu.Unlock()
		return
	}
}

func (s *Service) recoveryCandidate(ctx context.Context, snapshot recoverySnapshot) (candidate route, observed string, failure error) {
	if traceFrom(ctx) == nil {
		ctx = s.startProbeTrace(ctx, diagnosticRecovery, snapshot.generation, snapshot.attempt, snapshot.originCheckID)
	}
	defer func() { s.finishProbeTrace(ctx, failure) }()
	r, e := s.routeFor(ctx, snapshot.config, snapshot.secret, snapshot.username, snapshot.password)
	if e != nil {
		return nil, "", safeProbeError(e)
	}
	keep := false
	defer func() {
		if !keep {
			r.Close()
		}
	}()
	before, e := r.Fingerprint(ctx)
	if e != nil || before != snapshot.fingerprint {
		return nil, "", errRecoveryPath
	}
	ip, e := r.Probe(ctx, snapshot.config.ProbeURL)
	if e != nil {
		return nil, "", safeProbeError(e)
	}
	ip, e = validProbeIP(ip)
	if e != nil {
		return nil, "", e
	}
	if ip != snapshot.lastVerifiedIP || !expected(snapshot.config, ip) {
		return nil, ip, errRecoveryIP
	}
	after, e := r.Fingerprint(ctx)
	if e != nil || after != snapshot.fingerprint {
		return nil, "", errRecoveryPath
	}
	if e := ctx.Err(); e != nil {
		return nil, "", safeProbeError(e)
	}
	keep = true
	return r, ip, nil
}

func (s *Service) finishRecoveryBlocked(snapshot recoverySnapshot, reason, observed string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != snapshot.generation || s.status.State != "recovering" {
		return
	}
	s.closeLocked()
	s.status.State, s.status.Reason = "blocked", reason
	if ip, e := validProbeIP(observed); e == nil {
		s.status.ObservedIP = ip
		s.status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.eventLocked(reason)
}
