// Package nativeapp integrates separately installed Sandboxie Plus. Its native
// path is a preview and never establishes ExitGuard's required-mode proof.
package nativeapp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const Port = 17890
const RuntimeVersion = "5.73.8" // Sandboxie Plus v1.18.8, common/my_version.h.
var targets = map[string]string{"chrome": "chrome.exe", "edge": "msedge.exe", "claude": "Claude.exe"}

type LaunchPlan struct {
	Box  string
	Args []string
}

func box(target string) (string, error) {
	if _, ok := targets[target]; !ok {
		return "", errors.New("仅支持 chrome、edge、claude")
	}
	return "ExitGuard_" + strings.ToUpper(target[:1]) + target[1:], nil
}

// Policy has no templates, program exceptions, shared profiles or breakout
// entries. The same rule set applies to newly named descendants in the box.
func Policy(target string) (map[string][]string, error) {
	if _, err := box(target); err != nil {
		return nil, err
	}
	return map[string][]string{
		"Enabled": {"y"}, "ConfigLevel": {"10"}, "AutoRecover": {"n"},
		"DropAdminRights": {"y"}, "UseRuleSpecificity": {"n"}, "BlockSoftwareUpdaters": {"y"}, "NoSecurityIsolation": {"n"}, "NoSecurityFiltering": {"n"},
		"AllowNetworkAccess": {"y"}, "PromptForInternetAccess": {"n"}, "BlockLocalLoop": {"n"},
		"NetworkAccess": {"*,Block", "*,Allow;Address=127.0.0.1;Port=17890;Protocol=TCP"},
		"ClosedIpcPath": {`\RPC Control\DNSResolver`},
	}, nil
}

// VerifyEffective consumes values queried from the running driver, with global
// inheritance and templates included. Unknown settings fail closed: a policy
// change requires review, not another growing list of guessed exceptions.
func VerifyEffective(values map[string][]string) error {
	expected, _ := Policy("chrome")
	got := make(map[string][]string, len(values))
	for key, value := range values {
		lower := strings.ToLower(key)
		if _, duplicate := got[lower]; duplicate {
			return errors.New("运行时策略包含重复设置名")
		}
		got[lower] = value
	}
	for key, want := range expected {
		if !reflect.DeepEqual(got[strings.ToLower(key)], want) {
			return fmt.Errorf("运行时策略不匹配：%s（包括全局继承/模板）", key)
		}
		delete(got, strings.ToLower(key))
	}
	for key, want := range stockDefaults {
		lower := strings.ToLower(key)
		if values, exists := got[lower]; exists {
			if !reflect.DeepEqual(values, want) {
				return fmt.Errorf("默认模板设置发生变化：%s；不启动", key)
			}
			delete(got, lower)
		}
	}
	for key, value := range got {
		// This option only selects the runtime enforcement path. Actual installed
		// callouts/filters are checked separately; it is never a protection proof.
		if key == "networkenablewfp" && reflect.DeepEqual(value, []string{"y"}) {
			continue
		}
		return fmt.Errorf("存在未经审核的运行时设置：%s；不启动", key)
	}
	return nil
}

// WindowsPath rejects UNC/device paths, ADS, traversal and INI/command-line
// metacharacters. Go's host-dependent filepath helpers cannot validate Windows
// paths when policy tests are run on macOS.
func WindowsPath(path string) error {
	if len(path) < 4 || len(path) > 240 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1] != ':' || path[2] != '\\' || strings.ContainsAny(path[2:], ":\x00\r\n\"%[];|&<>?*`$") || strings.Contains(path, "/") {
		return errors.New("请使用无变量、无链接的本地完整 Windows 路径")
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.HasSuffix(part, ".") {
			return errors.New("Windows 路径包含不明确的部分")
		}
	}
	return nil
}

func Command(target, path, profile string) (LaunchPlan, error) {
	name, err := box(target)
	if err != nil {
		return LaunchPlan{}, err
	}
	if err := WindowsPath(path); err != nil {
		return LaunchPlan{}, err
	}
	if !strings.EqualFold(path[strings.LastIndex(path, `\`)+1:], targets[target]) {
		return LaunchPlan{}, errors.New("目标文件名与所选应用不符")
	}
	if err := WindowsPath(profile); err != nil {
		return LaunchPlan{}, err
	}
	args := []string{"/box:" + name, path, "--user-data-dir=" + profile, "--proxy-server=http://127.0.0.1:17890", "--proxy-bypass-list=<-loopback>;127.0.0.1:17890", "--disable-quic", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-background-networking", "--disable-extensions", "--no-first-run", "--no-default-browser-check"}
	if target != "claude" {
		args = append(args, "--new-window", "about:blank")
	}
	return LaunchPlan{Box: name, Args: args}, nil
}

func Snippet() []byte {
	var out strings.Builder
	out.WriteString("; ExitGuard native preview: new owned boxes only. No protection claim.\r\n")
	for _, target := range []string{"chrome", "edge", "claude"} {
		name, _ := box(target)
		p, _ := Policy(target)
		out.WriteString("\r\n[" + name + "]\r\n")
		keys := make([]string, 0, len(p))
		for k := range p {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range p[k] {
				out.WriteString(k + "=" + v + "\r\n")
			}
		}
	}
	return []byte(out.String())
}

// AppendOwnedBoxes is deliberately append-only. It refuses includes and unknown
// global settings; existing boxes, bytes, encoding and profiles are preserved.
// It NEVER changes NetworkEnableWFP, even when explicitly applying new boxes.
func AppendOwnedBoxes(previous []byte) ([]byte, error) {
	text, wide, err := decodeINI(previous)
	if err != nil {
		return nil, err
	}
	section := ""
	globals := map[string][]string{}
	sections := map[string]bool{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if sections[section] {
				return nil, errors.New("配置包含重复分组，无法安全追加")
			}
			sections[section] = true
			if strings.HasPrefix(section, "exitguard_") {
				return nil, errors.New("ExitGuard 分组已存在；不覆盖，请先检查现有分组")
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return nil, errors.New("INI 格式不受支持")
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if strings.EqualFold(k, "Include") || strings.EqualFold(k, "IncludeFile") {
			return nil, errors.New("配置使用外部 Include，无法核对全部有效设置")
		}
		if section == "globalsettings" {
			globals[strings.ToLower(k)] = append(globals[strings.ToLower(k)], v)
		}
	}
	if !reflect.DeepEqual(globals["networkenablewfp"], []string{"y"}) {
		return nil, errors.New("全局 NetworkEnableWFP 尚未明确启用；请在 Sandboxie 中审核其对已有箱的影响后自行启用，再重新暂存；ExitGuard 不代改全局设置")
	}
	// Existing global resource or breakout exceptions would also affect new boxes.
	for k := range globals {
		if k != "networkenablewfp" {
			return nil, fmt.Errorf("需先审核全局继承设置：%s；已有配置保持原样", k)
		}
	}
	addition := append([]byte("\r\n"), Snippet()...)
	if wide {
		units := utf16.Encode([]rune(string(addition)))
		addition = make([]byte, len(units)*2)
		for i, u := range units {
			binary.LittleEndian.PutUint16(addition[i*2:], u)
		}
	}
	return append(bytes.Clone(previous), addition...), nil
}

func decodeINI(data []byte) (string, bool, error) {
	if len(data) > 4<<20 {
		return "", false, errors.New("INI 文件过大")
	}
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) {
		if len(data)%2 != 0 {
			return "", false, errors.New("UTF-16 配置损坏")
		}
		units := make([]uint16, (len(data)-2)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(data[2+i*2:])
		}
		return string(utf16.Decode(units)), true, nil
	}
	if !utf8.Valid(data) || bytes.Contains(data, []byte{0}) {
		return "", false, errors.New("仅支持 UTF-8 或 UTF-16LE BOM 的 INI")
	}
	return strings.TrimPrefix(string(data), "\ufeff"), false, nil
}
