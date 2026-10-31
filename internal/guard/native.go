package guard

import (
	"context"
	"errors"
	"time"

	"exitguard/internal/nativeapp"
)

// LaunchNativePreview receives the live authenticated service session, never a
// report/token from disk. Preparation can be slow; the generation is checked
// again and process creation happens while mutations are excluded.
func (s *Service) LaunchNativePreview(ctx context.Context, target, path string, revision uint64, ack bool) error {
	if !ack {
		return errors.New("请先明确确认 Windows 原生预览尚未完成实机验收")
	}
	valid := func() bool {
		return s.running && s.config.EnforcementMode == "proxy-only" && s.config.ProxyPort == nativeapp.Port && s.status.State == "proxy_active" && s.status.EnforcementMode == "proxy-only" && s.status.ProxyAddress == "127.0.0.1:17890" && s.status.SessionRevision == revision
	}
	s.mu.Lock()
	ready := valid()
	prepare := s.prepareNative
	s.mu.Unlock()
	if !ready {
		return errors.New("需先启用当前 17890 端口的普通代理会话；原生预览不会更改严格模式")
	}
	if prepare == nil {
		prepare = nativeapp.Prepare
	}
	prepareCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cmd, err := prepare(prepareCtx, target, path)
	if err != nil {
		return err
	}
	if err := prepareCtx.Err(); err != nil {
		return errors.New("原生预览核验超时，启动已取消")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !valid() || prepareCtx.Err() != nil {
		return errors.New("代理会话已变化或操作已取消，原生预览启动已取消")
	}
	if cmd == nil {
		return errors.New("缺少经过核验的沙箱启动命令")
	}
	if err := cmd.Start(); err != nil {
		return errors.New("Sandboxie 未能启动目标；没有尝试普通启动")
	}
	go func() { _ = cmd.Wait() }()
	s.status.NativeState = "preview-incomplete"
	s.status.NativeReason = "已提交应用保护试用；尚未完成 Windows 实机测试，仅此入口新开的窗口在本次试用范围。"
	s.eventLocked(s.status.NativeReason)
	return nil
}
