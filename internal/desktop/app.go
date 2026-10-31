package desktop

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"exitguard/internal/guard"
	"github.com/egoist/mygo"
	native "github.com/egoist/mygo/ui"
)

func configPath(args []string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("无法定位本机配置目录，请检查当前账户的系统目录设置")
	}
	flags := flag.NewFlagSet("ExitGuard", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", filepath.Join(dir, "ExitGuard", "config.json"), "本机配置文件")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" {
		return "", errors.New("桌面程序仅接受 --config PATH；命令行诊断请使用独立的 exitguard 工具")
	}
	return *path, nil
}

// Run is a native, one-process application. Its view and guard exchange typed
// values in Go; it creates no Page, frontend, bearer URL or control listener.
func Run(args []string) error {
	mygo.App.SetName("ExitGuard")
	if !mygo.App.RequestSingleInstanceLock() {
		return nil
	}
	mygo.App.SetMenu(mygo.NewMenu([]*mygo.MenuItem{
		{Role: mygo.RoleAppMenu},
		{Role: mygo.RoleEditMenu},
		{Label: "窗口", Submenu: []*mygo.MenuItem{{Role: mygo.RoleMinimize}, {Role: mygo.RoleClose}}},
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path, startupErr := configPath(args)
	var service *guard.Service
	if startupErr == nil {
		service, startupErr = guard.New(path)
		if startupErr != nil {
			startupErr = errors.New("无法载入本机配置；请检查原 ExitGuard 配置文件的格式和访问权限")
		}
	}
	var win *mygo.Window
	var controller *Controller
	var runtimeMu sync.Mutex
	var running *ServiceRuntime
	started := make(chan struct{})
	if startupErr != nil {
		close(started)
	}
	message := ""
	if startupErr != nil {
		message = startupErr.Error()
	}
	mygo.App.OnSecondInstance(func(_ []string, _ string) {
		mygo.App.WhenReady(func() {
			if win != nil && !win.IsDestroyed() {
				win.Restore()
				win.Show()
				win.Focus()
			}
		})
	})
	stop := func() {
		cancel()
		if controller != nil {
			controller.Close()
		}
	}
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) { stop() })
	mygo.App.OnQuit(func() {
		stop()
		// A quit during startup cancels WaitReady and joins the starter first.
		select {
		case <-started:
		case <-time.After(4 * time.Second):
			return
		}
		runtimeMu.Lock()
		r := running
		runtimeMu.Unlock()
		if r != nil {
			r.Close(3 * time.Second)
		}
	})
	mygo.App.WhenReady(func() {
		if service != nil {
			controller = newController(ctx, service, func(f func()) { win.Update(f) }, Operations{})
			controller.Busy = true // startup owns the ordinary action slot
		}
		view := func(c *native.Context) {
			if message != "" {
				native.Column(c).Fill().Padding(32).Gap(18).Children(func() {
					native.Text(c, "ExitGuard 暂不可用").FontSize(25).Bold()
					native.Text(c, message).TextColor(c.Theme().Danger)
					native.Text(c, "转发入口保持关闭。修正问题后请退出并重新打开应用。")
					native.Button(c, "退出 ExitGuard").OnClick(mygo.App.Quit)
				})
				return
			}
			controller.View(c)
		}
		win = mygo.NewWindow(mygo.WindowOptions{Title: "ExitGuard", Width: 1120, Height: 840, MinWidth: 840, MinHeight: 620, Content: native.View(view)})
		win.OnClose(func(*mygo.CloseEvent) { stop() })
		if service == nil {
			return
		}
		go func() {
			r, profiles, err := startDesktopService(ctx, service)
			runtimeMu.Lock()
			running = r
			runtimeMu.Unlock()
			close(started)
			win.Update(func() {
				if controller.closed {
					return
				}
				controller.Busy = false
				if err != nil {
					message = err.Error()
					controller.Close()
					return
				}
				controller.completeProfileInitialization(profiles)
				controller.Discover()
			})
			if err != nil {
				return
			}
			go controller.Poll(ctx)
			<-r.Done()
			if ctx.Err() == nil {
				win.Update(func() {
					message = "守护代理已停止，转发入口已关闭；请重新打开 ExitGuard"
					controller.Close()
				})
			}
		}()
	})
	if err := mygo.App.Run(); err != nil {
		stop()
		return errors.New("无法启动原生桌面窗口；请检查系统版本和图形环境")
	}
	return nil
}
