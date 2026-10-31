package ui

import (
	"context"
	"debug/macho"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"exitguard/internal/model"
)

type launchRequest struct {
	Kind                    string  `json:"kind"`
	SessionRevision         *uint64 `json:"sessionRevision,omitempty"`
	Path                    string  `json:"path"`
	AcknowledgeProgramScope bool    `json:"acknowledgeProgramScope"`
}

func launchBrowser(service Service, request launchRequest) error {
	config, status := service.Config(), service.Status()
	dir, err := os.UserConfigDir()
	if err != nil {
		return errors.New("无法定位独立浏览器资料目录")
	}
	profile := filepath.Join(dir, "ExitGuard", "browser-profile-"+filepath.Base(request.Path)+"-"+strconv.Itoa(int(config.ProxyPort)))
	cmd, err := browserCommand(config, status, request, runtime.GOOS, profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(profile, 0700); err != nil {
		return errors.New("无法创建独立浏览器资料目录")
	}
	// No command shell and no inherited URL, token, profile, or browser arguments.
	return startIfArmed(service, status, cmd)
}

func browserCommand(c model.Config, s model.Status, r launchRequest, platform, profile string) (*exec.Cmd, error) {
	if r.Kind != "browser" {
		return nil, errors.New("此入口只支持已配置的 Chrome / Edge")
	}
	path, wantProxy, err := validatedTarget(c, s, r, platform)
	if err != nil {
		return nil, err
	}
	switch platform {
	case "windows":
		base := strings.ToLower(filepath.Base(path))
		if base != "chrome.exe" && base != "msedge.exe" {
			return nil, errors.New("仅支持 Chrome / Edge 的实际可执行文件")
		}
	case "darwin":
		base := filepath.Base(path)
		if base != "Google Chrome" && base != "Microsoft Edge" {
			return nil, errors.New("仅支持 Google Chrome / Microsoft Edge 的实际可执行文件")
		}
		if enforcementMode(c.EnforcementMode) == "required" {
			if err := verifyMacHelpers(path, c.Programs); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("当前平台尚未支持受保护浏览器启动")
	}
	if !filepath.IsAbs(profile) {
		return nil, errors.New("独立浏览器资料目录必须为绝对路径")
	}
	return exec.Command(path,
		"--user-data-dir="+profile,
		"--proxy-server=http://"+wantProxy,
		"--proxy-bypass-list=<-loopback>;"+wantProxy,
		"--disable-quic",
		"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-background-networking",
		"--disable-extensions",
		"--no-first-run",
		"--no-default-browser-check",
		"--new-window", "about:blank"), nil
}

// Empty mode is the legacy strict contract, never an implicit downgrade.
func enforcementMode(mode string) string {
	if mode == "" {
		return "required"
	}
	return mode
}

func launchReady(c model.Config, s model.Status) bool {
	mode := enforcementMode(c.EnforcementMode)
	if mode != enforcementMode(s.EnforcementMode) {
		return false
	}
	if mode == "proxy-only" {
		return s.State == "proxy_active" && !s.FilterActive
	}
	return mode == "required" && s.State == "armed" && s.FilterActive
}

func validatedTarget(c model.Config, s model.Status, r launchRequest, platform string) (string, string, error) {
	if !launchReady(c, s) {
		return "", "", errors.New("当前会话尚未启用或模式不匹配，禁止启动入口")
	}
	if r.SessionRevision != nil && *r.SessionRevision != s.SessionRevision {
		return "", "", errors.New("会话已变化，请刷新状态后重新选择启动入口")
	}
	strict := enforcementMode(c.EnforcementMode) == "required"
	if strict && !r.AcknowledgeProgramScope {
		return "", "", errors.New("请明确确认：程序级过滤会影响同一程序的所有资料目录和窗口")
	}
	path, err := canonicalExecutable(r.Path, platform)
	if err != nil {
		return "", "", err
	}
	if strict && !listedExecutable(path, c.Programs, platform) {
		return "", "", errors.New("所选程序未以规范化绝对路径列入当前系统过滤策略；请先添加实际路径并重新安装及验证策略")
	}
	wantProxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(c.ProxyPort)))
	if c.ProxyPort == 0 || s.ProxyAddress != wantProxy {
		return "", "", errors.New("代理地址与当前配置不匹配")
	}
	return path, wantProxy, nil
}

func claudeCommand(c model.Config, s model.Status, r launchRequest, platform string) (*exec.Cmd, error) {
	if r.Kind != "claude" {
		return nil, errors.New("无效的 Claude 启动请求")
	}
	path, proxy, err := validatedTarget(c, s, r, platform)
	if err != nil {
		return nil, err
	}
	if platform == "windows" {
		if !strings.EqualFold(filepath.Base(path), "Claude.exe") {
			return nil, errors.New("请选择 Claude.exe 的实际安装路径")
		}
	} else if platform == "darwin" {
		if filepath.Base(path) != "Claude" {
			return nil, errors.New("请选择 Claude.app/Contents/MacOS/Claude")
		}
		if enforcementMode(c.EnforcementMode) == "required" {
			if err := verifyMacHelpers(path, c.Programs); err != nil {
				return nil, err
			}
		}
	} else {
		return nil, errors.New("当前平台尚未支持 Claude 桌面端启动")
	}
	// Electron supports these switches, but a Claude version may override them.
	// Only required mode has a separate OS policy for non-proxy traffic.
	return exec.Command(path, "--proxy-server=http://"+proxy, "--proxy-bypass-list=<-loopback>;"+proxy, "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"), nil
}

func launchClaude(service Service, r launchRequest) error {
	c, s := service.Config(), service.Status()
	cmd, err := claudeCommand(c, s, r, runtime.GOOS)
	if err != nil {
		return err
	}
	if err := ensureClaudeStopped(cmd.Path, runtime.GOOS); err != nil {
		return err
	}
	return startIfArmed(service, s, cmd)
}

func startIfArmed(service Service, expected model.Status, command *exec.Cmd) error {
	current := service.Status()
	config := service.Config()
	if !launchReady(config, current) || current.State != expected.State || current.EnforcementMode != expected.EnforcementMode || current.FilterActive != expected.FilterActive || current.SessionRevision != expected.SessionRevision || current.PolicyHash != expected.PolicyHash || current.ProxyAddress != expected.ProxyAddress || current.ProxyAddress != net.JoinHostPort("127.0.0.1", strconv.Itoa(int(config.ProxyPort))) {
		return errors.New("会话状态已变化，启动已取消；请重新检查后再试")
	}
	if err := command.Start(); err != nil {
		return errors.New("目标程序未能启动，请检查安装文件与系统权限")
	}
	go func() { _ = command.Wait() }()
	return nil
}

func ensureClaudeStopped(path, platform string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if platform == "darwin" {
		app := filepath.Dir(filepath.Dir(filepath.Dir(path)))
		cmd := exec.CommandContext(ctx, "/usr/bin/pgrep", "-f", regexp.QuoteMeta(app+"/Contents/"))
		if err := cmd.Run(); err == nil {
			return errors.New("Claude 或其辅助进程已在运行。请先手动完全退出 Claude，再从此入口启动；本工具不会关闭现有进程")
		} else {
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == 1 {
				return nil
			}
			return errors.New("无法核对已有 Claude 进程，为避免复用未验证进程，本次不启动")
		}
	}
	if platform == "windows" {
		data, err := exec.CommandContext(ctx, "tasklist.exe", "/FI", "IMAGENAME eq Claude.exe", "/FO", "CSV", "/NH").Output()
		if err != nil {
			return errors.New("无法核对已有 Claude 进程，本次不启动")
		}
		if taskListHasImage(data, "Claude.exe") {
			return errors.New("Claude.exe 已在运行。请先手动完全退出，再从此入口启动；本工具不会关闭现有进程")
		}
		return nil
	}
	return errors.New("当前平台不支持进程检查")
}

func taskListHasImage(data []byte, name string) bool {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	for {
		record, err := r.Read()
		if err != nil {
			return false
		}
		if len(record) > 0 && strings.EqualFold(record[0], name) {
			return true
		}
	}
}

func canonicalExecutable(path, platform string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("目标程序必须使用完整绝对路径")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("未找到目标程序；请先安装客户端并填写实际可执行文件路径")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || (platform != "windows" && info.Mode().Perm()&0111 == 0) {
		return "", errors.New("目标路径不是可执行文件")
	}
	return filepath.Clean(resolved), nil
}

func listedExecutable(path string, programs []string, platform string) bool {
	for _, program := range programs {
		candidate, err := canonicalExecutable(program, platform)
		if err != nil {
			continue
		}
		// Native rules are keyed to stored paths. Resolving a configured symlink
		// only at launch could otherwise disagree with the attested OS policy.
		stored := filepath.Clean(program)
		if stored != candidate && !(platform == "windows" && strings.EqualFold(stored, candidate)) {
			continue
		}
		if candidate == path || (platform == "windows" && strings.EqualFold(candidate, path)) {
			return true
		}
	}
	return false
}

func verifyMacHelpers(main string, programs []string) error {
	macOS := filepath.Dir(main)
	contents := filepath.Dir(macOS)
	app := filepath.Dir(contents)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(app, ".app") {
		return errors.New("应用路径必须位于完整的 .app/Contents/MacOS 安装中")
	}
	mainExecutable, err := isMachOExecutable(main)
	if err != nil || !mainExecutable {
		return errors.New("主程序不是可验证的 Mach-O 可执行文件")
	}
	helperCount := 0
	seen := make(map[string]bool)
	err = filepath.WalkDir(contents, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(contents, resolved)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("应用包包含指向包外的链接，无法验证完整程序范围")
		}
		if !info.Mode().IsRegular() || seen[resolved] {
			return nil
		}
		seen[resolved] = true
		executable, err := isMachOExecutable(resolved)
		if err != nil {
			return fmt.Errorf("无法识别应用包内 Mach-O 文件：%w", err)
		}
		if !executable {
			return nil
		}
		if resolved != main {
			helperCount++
		}
		if !listedExecutable(resolved, programs, "darwin") {
			return fmt.Errorf("缺少辅助程序过滤路径：%s", resolved)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("应用辅助进程覆盖未就绪：%w", err)
	}
	if helperCount == 0 {
		return errors.New("未找到并验证应用辅助程序，拒绝启动")
	}
	return nil
}

// MH_EXECUTE covers packaged helpers such as chrome_crashpad_handler which are
// not nested .app bundles. Framework dylibs are intentionally not executables.
// Unknown/unparseable Mach-O layouts are rejected, rather than silently skipped.
func isMachOExecutable(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	be, le := binary.BigEndian.Uint32(magic[:]), binary.LittleEndian.Uint32(magic[:])
	if be == macho.Magic32 || be == macho.Magic64 || le == macho.Magic32 || le == macho.Magic64 {
		binary, err := macho.NewFile(file)
		if err != nil {
			return false, err
		}
		defer binary.Close()
		return binary.Type == macho.TypeExec, nil
	}
	if be == macho.MagicFat || be == 0xbebafeca || be == 0xcafebabf || be == 0xbfbafeca {
		binary, err := macho.NewFatFile(file)
		if err != nil {
			return false, err
		}
		defer binary.Close()
		for _, arch := range binary.Arches {
			if arch.Type == macho.TypeExec {
				return true, nil
			}
		}
	}
	return false, nil
}
