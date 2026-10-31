package desktop

import (
	"context"
	"errors"
	"time"

	"exitguard/internal/model"
)

type profileStartupCore interface {
	runningCore
	EnsureRemoteProfiles() error
	RemoteProfiles() ([]model.RemoteProfile, error)
}

// An existing desktop or CLI process may own the same configuration. Reserve
// its listener before migrating files, then keep forwarding closed throughout.
func startDesktopService(ctx context.Context, core profileStartupCore) (*ServiceRuntime, []model.RemoteProfile, error) {
	runtime, err := StartService(ctx, core)
	if err != nil {
		return nil, nil, err
	}
	err = core.EnsureRemoteProfiles()
	var profiles []model.RemoteProfile
	if err == nil {
		profiles, err = core.RemoteProfiles()
	}
	if err != nil {
		runtime.Close(3 * time.Second)
		return nil, nil, errors.New("无法初始化已保存代理；连接保持关闭，请检查本机代理配置文件后重新打开应用")
	}
	return runtime, profiles, nil
}
