package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"exitguard/internal/model"
)

type nativeConsoleService interface {
	Config() model.Config
	Status() model.Status
	Disarm()
	Arm(context.Context) error
	LaunchNativePreview(context.Context, string, string, uint64, bool) error
}

// This control runs inside the live core process, without a browser, tokens on
// command lines, report files or a second unauthenticated network endpoint.
func nativeConsole(ctx context.Context, service nativeConsoleService, input io.Reader, output io.Writer, openConfiguration func() error) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), 16<<10)
	fmt.Fprintln(output, "\nExitGuard · 应用保护试用窗口\n尚未完成 Windows 实机测试。先在配置页面启用代理，再完全退出 Chrome、Edge、Claude。\n以后从此窗口启动应用；普通快捷方式不在保护试用范围。此窗口不显示账户密码或控制凭证。\n按 Ctrl+C 可立即退出并停止本次代理。")
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Fprintln(output, "\n1 启动 Chrome（试用）  2 启动 Edge（试用）  3 启动 Claude（试用）\n4 查看状态  5 暂停代理  6 重新检查并启用代理  7 打开配置页面  0 退出\n请输入数字：")
		if !scanner.Scan() {
			return scanner.Err()
		}
		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "0":
			return nil
		case "1", "2", "3":
			target := map[string]string{"1": "chrome", "2": "edge", "3": "claude"}[choice]
			filename := map[string]string{"chrome": "chrome.exe", "edge": "msedge.exe", "claude": "Claude.exe"}[target]
			path := ""
			for _, candidate := range service.Config().Programs {
				normalized := strings.ReplaceAll(candidate, `\`, "/")
				if strings.EqualFold(normalized[strings.LastIndex(normalized, "/")+1:], filename) {
					path = candidate
					break
				}
			}
			if path != "" {
				fmt.Fprintf(output, "已配置路径：%s\n按回车使用，或输入其他完整路径（仅本次）：\n", path)
			} else {
				fmt.Fprintf(output, "请输入已安装 %s 的完整路径（仅本次）：\n", filename)
			}
			if !scanner.Scan() {
				return scanner.Err()
			}
			if typed := strings.TrimSpace(scanner.Text()); typed != "" {
				path = typed
			}
			if path == "" {
				fmt.Fprintln(output, "未选择应用路径；没有启动。")
				continue
			}
			// Input remains an argument consumed by Go validation; never a shell line.
			revision := service.Status().SessionRevision
			if err := service.LaunchNativePreview(ctx, target, path, revision, true); err != nil {
				fmt.Fprintln(output, "未启动：", err)
			} else {
				fmt.Fprintln(output, "已提交试用启动。请确认新窗口位于对应的 Sandboxie 分组；仍未完成 Windows 实机测试。")
			}
		case "4":
			status := service.Status()
			fmt.Fprintf(output, "当前代理状态：%s\n%s\n最近出口：%s\n应用保护试用：尚未完成 Windows 实机测试。\n", status.State, status.Reason, status.ObservedIP)
		case "5":
			service.Disarm()
			fmt.Fprintln(output, "代理已暂停。产品分组仍保留；可继续使用此窗口操作。")
		case "6":
			if err := service.Arm(ctx); err != nil {
				fmt.Fprintln(output, "代理未启用：", err)
			} else {
				fmt.Fprintln(output, "已请求重新检查并启用代理；应用保护试用仍未完成实机测试。")
			}
		case "7":
			if openConfiguration == nil {
				fmt.Fprintln(output, "配置页面暂不可用。")
			} else if err := openConfiguration(); err != nil {
				fmt.Fprintln(output, "配置页面未打开：", err)
			} else {
				fmt.Fprintln(output, "请完成配置后完全退出浏览器，再回到这个试用窗口启动应用。")
			}
		default:
			fmt.Fprintln(output, "请输入菜单中的数字；其他内容不会作为命令执行。")
		}
	}
}
