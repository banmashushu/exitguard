package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"exitguard/internal/diagnostics"
	"exitguard/internal/enforce"
	"exitguard/internal/guard"
	"exitguard/internal/nativeapp"
	"exitguard/internal/ui"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ExitGuard:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	if command == "help" || (len(args) > 0 && (args[0] == "--help" || args[0] == "-h")) {
		_, _ = io.WriteString(stdout, "ExitGuard — 本机固定出口控制\n\n  exitguard serve [--no-open] [--config PATH] [--native-console]\n  exitguard inspect [--config PATH]\n  exitguard native-template --output PATH  # 离线配置片段，不改系统\n  exitguard native-stage --output PATH     # 暂存三个新箱的配置计划\n  exitguard native-apply --plan PATH       # 显式应用已审核计划\n  exitguard native-inspect                 # Windows 原生预览前置检查\n  exitguard native-probe --target chrome   # 在产品箱内运行实际观测探针\n  exitguard doctor [--output PATH]  # 只读环境报告，不检查保护状态\n  exitguard filter-install [--config PATH]  # 仅在明确部署时执行，需要系统权限\n  exitguard filter-remove [--config PATH]   # 移除本产品规则\n\nserve/server 在守护代理的回环端口提供控制面板。stdout 仅输出一次含会话凭证的 ready JSON，请勿公开该输出。\n")
		return nil
	}
	if command == "native-template" || command == "native-stage" || command == "native-apply" || command == "native-inspect" || command == "native-probe" {
		nativeCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
		return nativeCommand(nativeCtx, command, args, stdout, stderr)
	}
	// Keep read-only diagnosis before config-directory lookup and guard.New.
	if command == "doctor" {
		return doctor(ctx, args, stdout, stderr)
	}
	if command != "serve" && command != "server" && command != "inspect" && command != "filter-install" && command != "filter-remove" {
		return errors.New("未知命令；使用 help 查看支持的操作")
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return errors.New("无法定位本机配置目录")
	}
	flags := flag.NewFlagSet("exitguard "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", filepath.Join(configDir, "ExitGuard", "config.json"), "本机配置文件")
	consoleMode := flags.Bool("native-console", false, "Windows 应用保护试用控制窗口，不依赖浏览器持续打开")
	noOpen := flags.Bool("no-open", false, "不自动打开控制面板")
	_ = flags.Bool("ready-json", true, "stdout 仅输出一次机器可读就绪消息")
	if err := flags.Parse(args); err != nil {
		return errors.New("命令参数无效")
	}
	if flags.NArg() != 0 {
		return errors.New("不接受额外参数")
	}
	if *consoleMode && runtime.GOOS != "windows" {
		return errors.New("应用保护试用窗口仅支持 Windows")
	}
	service, err := guard.New(*configPath)
	if err != nil {
		return err
	}
	if command == "serve" || command == "server" {
		return serve(ctx, service, *noOpen, *consoleMode, stdout, stderr)
	}
	c := service.Config()
	policy := enforce.Policy{Port: c.ProxyPort, Programs: c.Programs, BundleIDs: c.BundleIDs}
	operationTimeout := 45 * time.Second
	if command == "filter-install" {
		operationTimeout = 150 * time.Second
	}
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	switch command {
	case "inspect":
		proof, inspectErr := enforce.Inspect(operationCtx, policy)
		if err := json.NewEncoder(stdout).Encode(proof); err != nil {
			return err
		}
		if inspectErr != nil {
			return errors.New("系统过滤尚未就绪；详细原因见检查结果")
		}
		return nil
	case "filter-install":
		if err := enforce.Install(operationCtx, policy); err != nil {
			return err
		}
		_, _ = io.WriteString(stdout, "已请求安装当前策略。请执行 inspect 核对系统实际状态，再完成真实设备断线验证。\n")
	case "filter-remove":
		if err := enforce.Remove(operationCtx, policy); err != nil {
			return err
		}
		_, _ = io.WriteString(stdout, "已请求移除 ExitGuard 过滤策略。目标程序可能恢复普通网络访问。\n")
	}
	return nil
}

func serve(ctx context.Context, service *guard.Service, noOpen, consoleMode bool, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	control, launchURL, err := ui.NewControl(service, service.Status().ProxyAddress)
	if err != nil {
		return errors.New("无法启动本机控制面板")
	}
	defer service.Disarm()
	if err := service.SetControlHandler(control); err != nil {
		return err
	}
	results := make(chan error, 1)
	coreDone := make(chan struct{})
	go func() { defer close(coreDone); results <- service.Run(ctx) }()
	// Own shutdown as well as startup, including the final diagnostic marker.
	defer func() { cancel(); <-coreDone }()
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	if err := service.WaitReady(readyCtx); err != nil {
		return err
	}
	if !consoleMode {
		if err := json.NewEncoder(stdout).Encode(ui.Ready{Ready: true, URL: launchURL}); err != nil {
			return err
		}
	}
	if !noOpen && runtime.GOOS == "windows" {
		if err := openPanel(launchURL); err != nil {
			_, _ = io.WriteString(stderr, "控制面板未自动打开；请使用原生启动器或保密读取 ready 通道。\n")
		}
	}
	if consoleMode {
		go func() {
			_ = nativeConsole(ctx, service, os.Stdin, stderr, func() error {
				if err := nativeapp.RequireTargetsStopped(); err != nil {
					return err
				}
				return openPanel(launchURL)
			})
			cancel()
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-results:
		cancel()
		if err != nil {
			return err
		}
		return nil
	}
}

func openPanel(url string) error {
	// A single subprocess argument is passed directly; no shell interprets the
	// process token. Only a freshly generated loopback URL reaches this method.
	cmd := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// doctor never constructs a guard service or imports user proxy configuration.
func doctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("exitguard doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "只读诊断报告路径")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("doctor 参数无效；仅支持 --output PATH")
	}
	specified := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "output" {
			specified = true
		}
	})
	if specified && strings.TrimSpace(*output) == "" {
		return errors.New("报告路径不能为空")
	}
	report := diagnostics.Collect(ctx)
	var destination io.Writer = stdout
	var file *os.File
	if specified {
		var err error
		// Never replace an existing file or follow an existing report symlink.
		file, err = os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("无法创建诊断报告；请使用可写目录中的新文件名")
		}
		defer file.Close()
		destination = file
	}
	encoder := json.NewEncoder(destination)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return errors.New("无法写入诊断报告")
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return errors.New("无法保存诊断报告")
		}
	}
	return nil
}
