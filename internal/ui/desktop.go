package ui

import (
	"context"
	"errors"
)

// DesktopApplication is bounded installed-app inventory, not a protection proof.
type DesktopApplication = desktopApplication

// DiscoverApplications reuses the same bounded platform discovery as the legacy
// control panel. It neither launches a client nor reads its account/profile.
func DiscoverApplications(ctx context.Context) []DesktopApplication {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	return installedDesktopApplications(ctx)
}

// LaunchRequest carries an explicit current session and a chosen executable.
type LaunchRequest = launchRequest

// LaunchApplication is the shared typed entry to the existing launch gates.
// It accepts no URL or extra process arguments and performs no fallback launch.
func LaunchApplication(service Service, body LaunchRequest) error {
	current, config := service.Status(), service.Config()
	if (body.SessionRevision != nil && *body.SessionRevision != current.SessionRevision) || (enforcementMode(config.EnforcementMode) == "proxy-only" && body.SessionRevision == nil) {
		return errors.New("会话已变化，请刷新状态后重新选择启动入口")
	}
	if !launchReady(config, current) {
		return errors.New("当前会话尚未启用或模式不匹配，禁止启动入口")
	}
	switch body.Kind {
	case "browser":
		return launchBrowser(service, body)
	case "claude":
		return launchClaude(service, body)
	default:
		return errors.New("不支持此类程序启动")
	}
}
