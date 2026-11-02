package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func prepareClaudeProxyCommand(command *exec.Cmd, proxy string) error {
	account, err := user.Current()
	if err != nil || account.Username == "" || account.Username == "." || account.Username == ".." || filepath.Base(account.Username) != account.Username {
		return errors.New("无法核对当前用户的 Claude 应用专属代理策略，启动已取消")
	}
	const root = "/Library/Managed Preferences"
	const name = "com.anthropic.claudefordesktop.plist"
	return prepareClaudeManagedCommand(command, proxy, []string{filepath.Join(root, name), filepath.Join(root, account.Username, name)})
}

func prepareClaudeManagedCommand(command *exec.Cmd, proxy string, paths []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	values := make(map[string]string)
	// Claude merges the device plist first, then the current user's plist per
	// key. A PAC inherited from either scope wins over a fixed proxy URL.
	for _, path := range paths {
		data, err := readClaudeManagedPreferences(ctx, path)
		if err != nil {
			return errors.New("无法读取或验证 Claude 应用专属代理策略，启动已取消")
		}
		for _, key := range []string{"egressProxyUrl", "egressProxyPacUrl"} {
			if raw, present := data[key]; present {
				value, valid := raw.(string)
				if !valid || value == "" {
					return errors.New("Claude 应用专属代理策略无效，启动已取消")
				}
				values[key] = value
			}
		}
	}
	if values["egressProxyPacUrl"] != "" {
		return errors.New("Claude 的 PAC 策略会覆盖固定代理，无法确认使用当前本地入口，启动已取消")
	}
	if values["egressProxyUrl"] == "" {
		// Older clients may still accept the original explicit proxy switches.
		// Never fall back to an argument-free launch without a verified pin.
		return nil
	}
	if values["egressProxyUrl"] != "http://"+proxy {
		return errors.New("Claude 应用专属代理地址与当前本地入口不匹配，启动已取消")
	}
	macOS := filepath.Dir(command.Path)
	contents := filepath.Dir(macOS)
	if filepath.Base(command.Path) != "Claude" || filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(filepath.Dir(contents), ".app") {
		return errors.New("请选择完整 Claude.app/Contents/MacOS/Claude 安装路径")
	}
	metadata, err := bundleMetadata(ctx, filepath.Join(contents, "Info.plist"))
	if err != nil || metadata["CFBundleIdentifier"] != "com.anthropic.claudefordesktop" || metadata["CFBundleExecutable"] != "Claude" {
		return errors.New("无法验证 Claude 应用包身份，启动已取消")
	}
	if !claudeSupportsManagedProxy(metadata["CFBundleShortVersionString"]) {
		return errors.New("Claude 版本无法确认支持应用专属代理（至少需要 1.44121.1），启动已取消")
	}
	// The managed app policy supplies the proxy. Recent Claude versions reject
	// externally supplied Electron network switches before reading that policy.
	command.Args = []string{command.Path}
	return nil
}

func claudeSupportsManagedProxy(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	var numbers [3]uint64
	for i, part := range parts {
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return false
		}
		numbers[i] = value
	}
	// Earlier releases ignore these keys, so an old or unknown version must
	// never receive an argument-free launch based only on a matching plist.
	minimum := [3]uint64{1, 44121, 1}
	for i, value := range numbers {
		if value != minimum[i] {
			return value > minimum[i]
		}
	}
	return true
}

func readClaudeManagedPreferences(ctx context.Context, path string) (map[string]any, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleMetadata {
		return nil, errors.New("invalid managed preferences")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBundleMetadata+1))
	_ = f.Close()
	if err != nil || len(data) > maxBundleMetadata {
		return nil, errors.New("invalid managed preferences")
	}
	// Read a bounded snapshot, accepting XML and binary plists through macOS's
	// parser without reopening a mutable path or invoking the Claude client.
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", "-")
	cmd.Stdin = bytes.NewReader(data)
	var out boundedMetadata
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var values map[string]any
	if err := json.Unmarshal(out.Bytes(), &values); err != nil || values == nil {
		return nil, errors.New("invalid managed preferences")
	}
	return values, nil
}
