// Package guard owns a bounded local proxy with explicit optional OS enforcement.
package guard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"exitguard/internal/enforce"
	"exitguard/internal/model"
)

type route interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Fingerprint(context.Context) (string, error)
	Probe(context.Context, string) (string, error)
	Close() error
}
type Service struct {
	prepareNative   func(context.Context, string, string) (*exec.Cmd, error)
	mu              sync.Mutex
	checkMu         sync.Mutex
	configPath      string
	config          model.Config
	status          model.Status
	secret          string
	proxyUsername   string
	proxyPassword   string
	events          []model.Event
	generation      uint64
	connections     map[net.Conn]struct{}
	activeRoute     route
	fingerprint     string
	inspect         func(context.Context, enforce.Policy) (enforce.Proof, error)
	makeRoute       func(model.Config, string) (route, error)
	makeRemoteRoute func(context.Context, model.Config, string, string) (route, error)
	running         bool
	listener        net.Listener
	boundPort       uint16
	controlHandler  http.Handler
	readySignal     chan struct{}
	started         bool
	cancelCheck     context.CancelFunc
	cancelHealth    context.CancelFunc
	runContext      context.Context
	armedIntent     bool
	cancelRecovery  context.CancelFunc
	recoveryWait    func(context.Context, time.Duration) error
	recoverySlot    chan struct{}
}

func New(configPath string) (*Service, error) {
	c, e := loadConfig(configPath)
	if e != nil {
		return nil, e
	}
	s := &Service{configPath: configPath, config: c, readySignal: make(chan struct{}), connections: make(map[net.Conn]struct{}), inspect: enforce.Inspect, makeRoute: newRoute, makeRemoteRoute: newRemoteRoute, recoveryWait: waitRecovery, recoverySlot: make(chan struct{}, 1)}
	s.status = model.Status{State: "unconfigured", EnforcementMode: c.EnforcementMode, Reason: "尚未验证出口，本地代理入口保持关闭", Platform: runtime.GOOS, ProxyAddress: proxyAddress(c)}
	return s, nil
}
func (s *Service) Config() model.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyConfig(s.config)
}
func (s *Service) Status() model.Status { s.mu.Lock(); defer s.mu.Unlock(); return s.status }
func (s *Service) Events() []model.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Event(nil), s.events...)
}
func (s *Service) eventLocked(message string) {
	s.events = append(s.events, model.Event{At: time.Now().UTC().Format(time.RFC3339), State: s.status.State, Message: message})
	if len(s.events) > 100 {
		s.events = append([]model.Event(nil), s.events[len(s.events)-100:]...)
	}
}
func (s *Service) closeLocked() {
	s.armedIntent = false
	if s.cancelRecovery != nil {
		s.cancelRecovery()
		s.cancelRecovery = nil
	}
	s.status.RecoveryAttempt, s.status.RecoveryMaxAttempts, s.status.NextRetryAt = 0, 0, ""
	if s.cancelCheck != nil {
		s.cancelCheck()
		s.cancelCheck = nil
	}
	if s.cancelHealth != nil {
		s.cancelHealth()
		s.cancelHealth = nil
	}
	s.generation++
	s.status.SessionRevision = s.generation
	s.status.FilterActive = false
	s.status.PolicyHash = ""
	for c := range s.connections {
		_ = c.Close()
		delete(s.connections, c)
	}
	if s.activeRoute != nil {
		_ = s.activeRoute.Close()
		s.activeRoute = nil
	}
	s.fingerprint = ""
}
func (s *Service) SaveConfig(c model.Config) error {
	c = defaults(copyConfig(c))
	if e := validateConfig(c, false); e != nil {
		s.mu.Lock()
		s.closeLocked()
		s.status.State, s.status.Reason = "blocked", e.Error()
		s.eventLocked("配置无效，入口已关闭")
		s.mu.Unlock()
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.config
	s.closeLocked()
	if s.running && c.ProxyPort != s.config.ProxyPort {
		s.status.State = "blocked"
		s.status.Reason = "运行中不能更改守护端口，请先停止服务再修改配置"
		s.eventLocked(s.status.Reason)
		return errors.New(s.status.Reason)
	}
	s.status.State = "unconfigured"
	s.status.FilterActive = false
	s.status.PolicyHash = ""
	s.status.ObservedIP = ""
	s.status.Reason = "配置已变化，需要重新验证"
	if e := persistConfig(s.configPath, c); e != nil {
		s.status.State = "blocked"
		s.status.Reason = e.Error()
		s.eventLocked("配置保存失败，入口已关闭")
		return e
	}
	s.config = c
	if c.Mode != "remote" || c.Mode != old.Mode || c.ProxyURL != old.ProxyURL {
		s.proxyUsername, s.proxyPassword = "", ""
		s.status.UpstreamCredentialsSet = false
	}
	s.status.EnforcementMode = c.EnforcementMode
	s.status.ProxyAddress = proxyAddress(c)
	s.eventLocked("配置已保存，入口已关闭")
	return nil
}

// SetProxyCredentials retains credentials only for this process and this endpoint.
// It never adds credentials to configuration, events, URLs or status snapshots.
func (s *Service) SetProxyCredentials(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	e := validateProxyCredentials(username, password)
	if s.config.Mode != "remote" && username != "" {
		e = errors.New("仅远程代理模式接受代理凭证")
	}
	if e != nil {
		s.proxyUsername, s.proxyPassword = "", ""
		s.status.UpstreamCredentialsSet = false
		s.status.State, s.status.Reason = "blocked", e.Error()
		s.eventLocked("代理凭证无效，入口已关闭")
		return e
	}
	s.proxyUsername, s.proxyPassword = username, password
	s.status.UpstreamCredentialsSet = username != ""
	s.status.State = "unconfigured"
	s.status.Reason = "代理会话凭证已更新，需要重新验证"
	s.eventLocked(s.status.Reason)
	return nil
}
func validateProxyCredentials(username, password string) error {
	if (username == "") != (password == "") || len(username) > 255 || len(password) > 255 || strings.Contains(username, ":") {
		return errors.New("代理凭证格式无效，用户名和密码须同时填写或同时清除")
	}
	for _, value := range []string{username, password} {
		for _, c := range value {
			if c < 0x20 || c == 0x7f {
				return errors.New("代理凭证不能包含控制字符")
			}
		}
	}
	return nil
}
func (s *Service) SetSecret(secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	s.secret = secret
	s.status.State = "unconfigured"
	s.status.FilterActive = false
	s.status.Reason = "控制凭证已更新，需要重新验证"
	s.eventLocked("会话凭证已更新")
}
func (s *Service) Disarm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	s.status.State = "stopped"
	s.status.Reason = "保护入口已暂停"
	s.eventLocked(s.status.Reason)
}
func (s *Service) block(g uint64, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != g {
		return errors.New("验证已取消，需要重新检查")
	}
	s.closeLocked()
	s.status.State = "blocked"
	s.status.Reason = reason
	s.status.FilterActive = false
	s.eventLocked(reason)
	return errors.New(reason)
}

func (s *Service) blockProbe(g uint64, ctx context.Context, stage string, failure error, observed string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != g {
		return errors.New("验证已取消，需要重新检查")
	}
	// closeLocked cancels the current probe, so capture its context first.
	if e := ctx.Err(); e != nil {
		failure, observed = e, ""
	}
	reason := "公网出口与期望 IP 不符，入口已关闭"
	if failure != nil {
		reason = stage + safeProbeError(failure).Error()
		observed = ""
		if transientRecoveryFailure(failure) && s.beginRecoveryLocked(g, reason) {
			return errors.New(reason)
		}
	} else {
		var e error
		observed, e = validProbeIP(observed)
		if e != nil {
			reason = stage + safeProbeError(e).Error()
		}
	}
	s.closeLocked()
	s.status.State, s.status.Reason = "blocked", reason
	if observed != "" {
		s.status.ObservedIP = observed
		s.status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.eventLocked(reason)
	return errors.New(reason)
}
func policy(c model.Config) enforce.Policy {
	return enforce.Policy{Port: c.ProxyPort, Programs: c.Programs, BundleIDs: c.BundleIDs}
}
func expected(c model.Config, raw string) bool {
	ip, e := netip.ParseAddr(raw)
	if e != nil {
		return false
	}
	for _, v := range c.ExpectedIPs {
		want, e := netip.ParseAddr(v)
		if e == nil && want.Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}
func (s *Service) Check(ctx context.Context) error { return s.validate(ctx, false) }
func (s *Service) Arm(ctx context.Context) error   { return s.validate(ctx, true) }
func (s *Service) validate(ctx context.Context, arm bool) error {
	if !s.checkMu.TryLock() {
		return errors.New("已有验证任务正在运行，请等待或暂停")
	}
	defer s.checkMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s.mu.Lock()
	s.closeLocked()
	g := s.generation
	s.cancelCheck = cancel
	c := copyConfig(s.config)
	secret := s.secret
	username, password := s.proxyUsername, s.proxyPassword
	s.status.State = "checking"
	s.status.Reason = "正在核验指定出口"
	s.status.FilterActive = false
	s.status.ObservedIP = ""
	s.status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	s.mu.Unlock()
	if arm {
		s.mu.Lock()
		owned := s.running && s.listener != nil && s.boundPort == c.ProxyPort
		s.mu.Unlock()
		if !owned {
			return s.block(g, "守护服务尚未独占当前配置端口，无法启用保护")
		}
	}
	if e := validateConfig(c, true); e != nil {
		return s.block(g, e.Error())
	}
	var proof enforce.Proof
	var e error
	if c.EnforcementMode == "required" {
		proof, e = s.inspect(ctx, policy(c))
		if e != nil || !proof.Active || proof.PolicyHash != enforce.Hash(policy(c)) {
			return s.block(g, "系统过滤未安装、未启用或与当前目标配置不匹配")
		}
	}
	r, e := s.routeFor(ctx, c, secret, username, password)
	if e != nil {
		return s.block(g, e.Error())
	}
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	before, e := r.Fingerprint(ctx)
	if e != nil || before == "" {
		return s.block(g, "出口路径尚未验证或不支持当前配置")
	}
	ip, e := r.Probe(ctx, c.ProbeURL)
	if e == nil {
		ip, e = validProbeIP(ip)
	}
	if e != nil {
		return s.blockProbe(g, ctx, "公网出口检查失败：", e, "")
	}
	if !expected(c, ip) {
		return s.blockProbe(g, ctx, "公网出口检查失败：", nil, ip)
	}
	after, e := r.Fingerprint(ctx)
	if e != nil || after != before {
		return s.block(g, "验证期间出口路径发生变化")
	}
	if c.EnforcementMode == "required" {
		proof, e = s.inspect(ctx, policy(c))
		if e != nil || !proof.Active || proof.PolicyHash != enforce.Hash(policy(c)) {
			return s.block(g, "验证期间系统过滤失效")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g != s.generation {
		return errors.New("验证已取消，需要重新检查")
	}
	if ctx.Err() != nil || arm && (!s.running || s.listener == nil || s.boundPort != c.ProxyPort) {
		s.closeLocked()
		s.status.State = "blocked"
		s.status.Reason = "验证已取消或本地监听已停止，需要重新检查"
		s.eventLocked(s.status.Reason)
		return errors.New(s.status.Reason)
	}
	s.activeRoute = r
	s.fingerprint = after
	s.armedIntent = arm
	keep = true
	s.status.State = "ready"
	s.status.Reason = "入口已验证，可启用保护；真实客户端与断线验收仍需单独完成"
	if arm {
		s.status.State = "armed"
		s.status.Reason = "本地入口已启用；出口变化检测存在时间窗口"
	}
	s.status.ObservedIP = ip
	s.status.FilterActive = true
	s.status.PolicyHash = proof.PolicyHash
	if c.EnforcementMode == "proxy-only" {
		s.status.State = "proxy_ready"
		s.status.Reason = "代理出口已验证，可启用转发；仅代理转发，系统防绕行未验证"
		if arm {
			s.status.State = "proxy_active"
			s.status.Reason = "代理运行中；仅代理转发，系统防绕行未验证；仅转发使用本代理的 IPv4 TCP 流量"
		}
		s.status.FilterActive = false
		s.status.PolicyHash = ""
	}
	s.eventLocked(s.status.Reason)
	return nil
}
func (s *Service) track(c net.Conn, g uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !activeState(s.status.State) || s.generation != g {
		_ = c.Close()
		return false
	}
	s.connections[c] = struct{}{}
	return true
}
func (s *Service) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.connections, c)
	s.mu.Unlock()
	_ = c.Close()
}
func (s *Service) admission() (route, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeRoute, s.generation, activeState(s.status.State) && s.activeRoute != nil
}
func activeState(state string) bool { return state == "armed" || state == "proxy_active" }
func (s *Service) routeFor(ctx context.Context, c model.Config, secret, username, password string) (route, error) {
	if c.Mode == "remote" {
		return s.makeRemoteRoute(ctx, c, username, password)
	}
	return s.makeRoute(c, secret)
}
func (s *Service) health(ctx context.Context) {
	s.mu.Lock()
	if !activeState(s.status.State) || s.activeRoute == nil {
		s.mu.Unlock()
		return
	}
	g, c, r, fp := s.generation, copyConfig(s.config), s.activeRoute, s.fingerprint
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	s.mu.Lock()
	if s.generation != g || !activeState(s.status.State) {
		s.mu.Unlock()
		return
	}
	s.cancelHealth = cancel
	s.mu.Unlock()
	if c.EnforcementMode == "required" {
		p, e := s.inspect(ctx, policy(c))
		if e != nil || !p.Active || p.PolicyHash != enforce.Hash(policy(c)) {
			_ = s.block(g, "系统过滤状态变化，入口已关闭")
			return
		}
	}
	next, e := r.Fingerprint(ctx)
	if e != nil || fp != next {
		_ = s.block(g, "出口路径变化，入口已关闭")
		return
	}
	ip, e := r.Probe(ctx, c.ProbeURL)
	if e == nil {
		ip, e = validProbeIP(ip)
	}
	if e != nil {
		_ = s.blockProbe(g, ctx, "公网出口检查失败：", e, "")
		return
	}
	if !expected(c, ip) {
		_ = s.blockProbe(g, ctx, "公网出口检查失败：", nil, ip)
		return
	}
	s.mu.Lock()
	if g == s.generation && ctx.Err() == nil {
		s.status.ObservedIP = ip
		s.status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.mu.Unlock()
}

// ProbeCandidate discovers only this process's route. It never authorizes application traffic.
func (s *Service) ProbeCandidate(ctx context.Context) (string, error) {
	if !s.checkMu.TryLock() {
		return "", errors.New("已有验证任务正在运行，请等待或暂停")
	}
	defer s.checkMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s.mu.Lock()
	s.closeLocked()
	g, c, secret := s.generation, copyConfig(s.config), s.secret
	username, password := s.proxyUsername, s.proxyPassword
	s.cancelCheck = cancel
	s.status.State = "checking"
	s.status.FilterActive = false
	s.status.ObservedIP = ""
	s.status.Reason = "正在探测守护进程的候选出口"
	s.mu.Unlock()
	if e := validateConfig(c, false); e != nil {
		return "", s.block(g, e.Error())
	}
	r, e := s.routeFor(ctx, c, secret, username, password)
	if e != nil {
		return "", s.block(g, e.Error())
	}
	defer r.Close()
	before, e := r.Fingerprint(ctx)
	if e != nil || before == "" {
		return "", s.block(g, "候选出口路径不可用")
	}
	ip, e := r.Probe(ctx, c.ProbeURL)
	if e == nil {
		ip, e = validProbeIP(ip)
	}
	if e != nil {
		return "", s.blockProbe(g, ctx, "候选出口探测失败：", e, "")
	}
	after, e := r.Fingerprint(ctx)
	if e != nil || after != before {
		return "", s.block(g, "候选出口路径已变化")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g != s.generation {
		return "", errors.New("候选探测已取消")
	}
	if ctx.Err() != nil {
		s.status.State = "blocked"
		s.status.Reason = "候选探测已取消"
		s.eventLocked(s.status.Reason)
		return "", errors.New(s.status.Reason)
	}
	s.status.State = "blocked"
	s.status.ObservedIP = ip
	s.status.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	s.status.Reason = "仅为守护进程的候选出口，未证明 Claude 路径；请另行确认固定性后填写期望 IP"
	s.eventLocked(s.status.Reason)
	return ip, nil
}

// SetControlHandler shares the fixed local port with authenticated origin-form controls.
// It must be configured before Run; it cannot authorize proxy forwarding.
func (s *Service) SetControlHandler(h http.Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("控制界面必须在守护服务启动前配置")
	}
	if h == nil {
		return errors.New("控制处理器不能为空")
	}
	s.controlHandler = h
	return nil
}
func (s *Service) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.readySignal:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.listener == nil || s.boundPort != s.config.ProxyPort {
		return errors.New("守护服务未能独占配置端口")
	}
	return nil
}
