package ui

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

const chromeExecutable = "Google Chrome"

type claudeProxyKeyRemoval struct {
	path, key string
}

// RemoveClaudeProxy clears the pinned proxy settings after macOS authorizes
// the write. Claude reads them again when the user reopens it.
func RemoveClaudeProxy(ctx context.Context) (bool, error) {
	account, err := user.Current()
	if err != nil || account.Username == "" || account.Username == "." || account.Username == ".." || filepath.Base(account.Username) != account.Username {
		return false, errors.New("无法核对当前用户的 Claude 配置")
	}
	const root = "/Library/Managed Preferences"
	const name = "com.anthropic.claudefordesktop.plist"
	paths := []string{filepath.Join(root, name), filepath.Join(root, account.Username, name)}
	return removeClaudeProxyPreferences(ctx, paths, removeClaudeProxyAsAdmin)
}

func removeClaudeProxyPreferences(ctx context.Context, paths []string, apply func(context.Context, []claudeProxyKeyRemoval) error) (bool, error) {
	removals, err := claudeProxyKeysPresent(ctx, paths)
	if err != nil || len(removals) == 0 {
		return false, err
	}
	writeErr := apply(ctx, removals)
	remaining, err := claudeProxyKeysPresent(ctx, paths)
	if err == nil && len(remaining) == 0 {
		return true, nil
	}
	if writeErr != nil {
		return false, writeErr
	}
	if err != nil {
		return false, errors.New("无法核对 Claude 代理移除结果，请重试")
	}
	return false, errors.New("Claude 代理配置仍存在。若由描述文件下发，请在系统设置的「设备管理」检查")
}

func claudeProxyKeysPresent(ctx context.Context, paths []string) ([]claudeProxyKeyRemoval, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	var removals []claudeProxyKeyRemoval
	for _, path := range paths {
		keys, err := readManagedPreferenceKeys(ctx, path)
		if err != nil {
			return nil, errors.New("无法读取 Claude 的本机代理配置")
		}
		for _, key := range []string{"egressProxyUrl", "egressProxyPacUrl"} {
			if slices.Contains(keys, key) {
				removals = append(removals, claudeProxyKeyRemoval{path, key})
			}
		}
	}
	return removals, nil
}

func readManagedPreferenceKeys(ctx context.Context, path string) ([]string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleMetadata {
		return nil, errors.New("invalid managed preferences")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBundleMetadata+1))
	_ = file.Close()
	if err != nil || len(data) > maxBundleMetadata {
		return nil, errors.New("invalid managed preferences")
	}
	// XML can represent every plist value type, including unrelated dates and
	// binary data. Only the names of the top-level entries are needed here.
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "--", "-")
	cmd.Stdin = bytes.NewReader(data)
	var out boundedMetadata
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var plist struct {
		XMLName xml.Name `xml:"plist"`
		Dict    *struct {
			Keys []string `xml:"key"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(out.Bytes(), &plist); err != nil || plist.Dict == nil {
		return nil, errors.New("invalid managed preferences")
	}
	return plist.Dict.Keys, nil
}

// The command and key paths are fixed by the app. Quote the arguments again
// for the shell used by macOS to run the authorized command.
const removeClaudeProxyScript = `
on run argv
	set shellCommand to "set -e" & linefeed
	repeat with i from 1 to (count of argv) by 2
		set shellCommand to shellCommand & "/usr/bin/plutil -remove " & (quoted form of (item i of argv)) & " -- " & (quoted form of (item (i + 1) of argv)) & linefeed
	end repeat
	do shell script shellCommand with administrator privileges
end run
`

func removeClaudeProxyAsAdmin(ctx context.Context, removals []claudeProxyKeyRemoval) error {
	args := []string{"-e", removeClaudeProxyScript}
	for _, removal := range removals {
		if !protectedManagedPreferencePath(ctx, removal.path) {
			return errors.New("Claude 配置文件的位置或权限异常，无法移除代理")
		}
		args = append(args, removal.key, removal.path)
	}
	if _, err := exec.CommandContext(ctx, "/usr/bin/osascript", args...).Output(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && strings.Contains(string(exit.Stderr), "(-128)") {
			return errors.New("已取消管理员授权")
		}
		return errors.New("Claude 代理移除未完成，请确认管理员授权后重试")
	}
	return nil
}

// Reject symlinks and locations a non-root process can replace before
// the authorization dialog completes.
func protectedManagedPreferencePath(ctx context.Context, path string) bool {
	for location := path; location != "/"; location = filepath.Dir(location) {
		info, err := os.Lstat(location)
		if err != nil || (location == path && !info.Mode().IsRegular()) || (location != path && !info.IsDir()) {
			return false
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		// Extended ACL entries are printed on separate lines and can grant
		// write access independently of the POSIX mode.
		listing, err := exec.CommandContext(ctx, "/bin/ls", "-dle", "--", location).Output()
		if err != nil || bytes.Count(listing, []byte{'\n'}) != 1 {
			return false
		}
	}
	return true
}

// LaunchChromeWithoutProxy uses Chrome's normal profile. It is independent of
// the protected launch, which always uses an isolated ExitGuard profile.
func LaunchChromeWithoutProxy(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	cmd, err := macChromeWithoutProxyCommand(ctx, path)
	if err != nil {
		return err
	}
	// Stable Chrome shares its default data directory across installations.
	// Look for the main Chrome process under this user, regardless of its path.
	err = exec.CommandContext(ctx, "/usr/bin/pgrep", "-u", strconv.Itoa(os.Geteuid()), "-x", chromeExecutable).Run()
	if err == nil {
		return errors.New("请先完全退出 Chrome，包括独立代理窗口，再无代理启动")
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		return errors.New("无法核对 Chrome 是否已完全退出")
	}
	if err := cmd.Run(); err != nil {
		return errors.New("无法启动 Chrome，请检查应用安装")
	}
	return nil
}

func macChromeWithoutProxyCommand(ctx context.Context, path string) (*exec.Cmd, error) {
	path, err := canonicalExecutable(path, "darwin")
	if err != nil {
		return nil, err
	}
	macOS := filepath.Dir(path)
	contents := filepath.Dir(macOS)
	bundle := filepath.Dir(contents)
	if filepath.Base(path) != chromeExecutable || filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || filepath.Ext(bundle) != ".app" {
		return nil, errors.New("请选择 Google Chrome.app 中的主可执行文件")
	}
	metadata, err := bundleMetadata(ctx, filepath.Join(contents, "Info.plist"))
	if err != nil || metadata["CFBundleIdentifier"] != "com.google.Chrome" || metadata["CFBundleExecutable"] != chromeExecutable {
		return nil, errors.New("无法验证 Google Chrome 应用包")
	}
	return exec.CommandContext(ctx, "/usr/bin/open", "-a", bundle, "--args", "--no-proxy-server"), nil
}
