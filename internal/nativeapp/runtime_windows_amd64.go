//go:build windows && amd64

package nativeapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"exitguard/internal/enforce"
)

type installedRuntime struct {
	home       string
	dll        *syscall.DLL
	signatures []SignatureEvidence
}

func systemPowerShell() (string, error) {
	var buffer [32768]uint16
	n, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return "", errors.New("无法定位 Windows 系统目录")
	}
	return filepath.Join(syscall.UTF16ToString(buffer[:n]), `WindowsPowerShell\v1.0\powershell.exe`), nil
}

// Only a fixed program is interpreted. File paths travel in a private child
// environment variable and are passed to -LiteralPath, never interpolated.
func signatureFile(ctx context.Context, path, kind string) (SignatureEvidence, error) {
	evidence := SignatureEvidence{File: filepath.Base(path)}
	if err := regularLocal(path); err != nil {
		return evidence, err
	}
	shell, err := systemPowerShell()
	if err != nil {
		return evidence, err
	}
	cmd := exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $env:EXITGUARD_NATIVE_VERIFY; $v=(Get-Item -LiteralPath $env:EXITGUARD_NATIVE_VERIFY).VersionInfo; @{valid=($s.Status -eq 'Valid');publisher=$s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);thumbprint=$s.SignerCertificate.Thumbprint;version=$v.FileVersion;product=$v.ProductName}|ConvertTo-Json -Compress`)
	cmd.Env = append(os.Environ(), "EXITGUARD_NATIVE_VERIFY="+path)
	data, err := cmd.Output()
	if err != nil {
		return evidence, errors.New("无法核验程序数字签名，取消原生操作")
	}
	var result SignatureEvidence
	if len(data) > 8192 || json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &result) != nil {
		return evidence, errors.New("无法读取文件签名信息")
	}
	result.File = evidence.File
	evidence = result
	if !acceptSignature(result, kind) {
		return evidence, &signatureError{Evidence: evidence, Reason: "文件的 Windows 签名、发布者或版本不在审核范围；请保留 native-inspect 中的签名信息供核对，不加载未知 DLL"}
	}
	return evidence, nil
}

func signedFile(ctx context.Context, path, kind string) error {
	_, err := signatureFile(ctx, path, kind)
	return err
}

func regularLocal(path string) error {
	if err := WindowsPath(path); err != nil {
		return err
	}
	current := path
	for len(current) > 3 {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("原生操作需要已存在的本地路径")
		}
		data, ok := info.Sys().(*syscall.Win32FileAttributeData)
		if !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("不支持链接、重解析点或不明确的本地文件")
		}
		if current == path && !info.Mode().IsRegular() {
			return errors.New("目标不是普通文件")
		}
		current = filepath.Dir(current)
	}
	return nil
}

func registryString(keyPath, value string) (string, error) {
	keyName, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, keyName, 0, syscall.KEY_READ, &key); err != nil {
		return "", errors.New("缺少组件：未找到已安装的 Sandboxie 服务；请先安装官方 Sandboxie Plus v1.18.8 x64")
	}
	defer syscall.RegCloseKey(key)
	name, _ := syscall.UTF16PtrFromString(value)
	var typ uint32
	size := uint32(65534)
	data := make([]uint16, size/2)
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, (*byte)(unsafe.Pointer(&data[0])), &size); err != nil || (typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ) || size < 2 || size > 65534 {
		return "", errors.New("Sandboxie 服务路径不可读取")
	}
	return syscall.UTF16ToString(data), nil
}

func installed(ctx context.Context) (*installedRuntime, error) {
	raw, err := registryString(`SYSTEM\CurrentControlSet\Services\SbieSvc`, "ImagePath")
	if err != nil {
		return nil, err
	}
	service := strings.TrimSpace(raw)
	if strings.HasPrefix(service, `"`) && strings.HasSuffix(service, `"`) {
		service = service[1 : len(service)-1]
	}
	if !strings.EqualFold(filepath.Base(service), "SbieSvc.exe") {
		return nil, errors.New("Sandboxie 服务命令包含未经审核的参数")
	}
	home := filepath.Dir(service)
	var signatures []SignatureEvidence
	for _, name := range []string{"SbieSvc.exe", "Start.exe", "SbieDll.dll"} {
		evidence, err := signatureFile(ctx, filepath.Join(home, name), "runtime")
		signatures = append(signatures, evidence)
		if err != nil {
			return nil, err
		}
	}
	raw, err = registryString(`SYSTEM\CurrentControlSet\Services\SbieDrv`, "ImagePath")
	if err != nil {
		return nil, err
	}
	driver := strings.Trim(raw, `"`)
	if strings.HasPrefix(driver, `\??\`) {
		driver = strings.TrimPrefix(driver, `\??\`)
	}
	if !strings.EqualFold(filepath.Base(driver), "SbieDrv.sys") {
		return nil, errors.New("Sandboxie 驱动路径无效")
	}
	evidence, err := signatureFile(ctx, driver, "driver")
	signatures = append(signatures, evidence)
	if err != nil {
		return nil, err
	}
	path, _ := syscall.UTF16PtrFromString(filepath.Join(home, "SbieDll.dll"))
	handle, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW").Call(uintptr(unsafe.Pointer(path)), 0, 0x900) // DLL_LOAD_DIR | SYSTEM32; no application/user-added search directories
	if handle == 0 {
		return nil, errors.New("无法安全加载已安装的 Sandboxie API")
	}
	r := &installedRuntime{signatures: signatures, home: home, dll: &syscall.DLL{Name: "SbieDll.dll", Handle: syscall.Handle(handle)}}
	var version [16]uint16
	var abi uint32
	code, err := r.call("SbieApi_GetVersionEx", uintptr(unsafe.Pointer(&version[0])), uintptr(unsafe.Pointer(&abi)))
	if err != nil || code != 0 || syscall.UTF16ToString(version[:]) != RuntimeVersion || abi != 0x57230 {
		r.dll.Release()
		return nil, errors.New("运行中驱动不是已审核的 5.73.8 / ABI 0x57230；请重启后核对安装版本")
	}
	return r, nil
}

//go:uintptrescapes
func (r *installedRuntime) call(name string, args ...uintptr) (uintptr, error) {
	p, err := r.dll.FindProc(name)
	if err != nil {
		return 0, errors.New("已安装运行时缺少所需的官方 API")
	}
	code, _, _ := p.Call(args...)
	return uintptr(uint32(code)), nil
}

func (r *installedRuntime) query(section, key string, index uint32) (string, bool, error) {
	var sec, setting *uint16
	if section != "" {
		sec, _ = syscall.UTF16PtrFromString(section)
	}
	if key != "" {
		setting, _ = syscall.UTF16PtrFromString(key)
	}
	buffer := make([]uint16, 32767)
	code, err := r.call("SbieApi_QueryConf", uintptr(unsafe.Pointer(sec)), uintptr(unsafe.Pointer(setting)), uintptr(index|0x20000000), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)*2))
	if err != nil {
		return "", false, err
	}
	if code == 0xc000008b {
		return "", false, nil
	}
	if code != 0 {
		return "", false, fmt.Errorf("运行时配置查询失败（0x%08x），未将错误当作空列表", code)
	}
	return syscall.UTF16ToString(buffer), true, nil
}

func (r *installedRuntime) effective(boxName string) (map[string][]string, error) {
	keys := map[string]bool{}
	for _, section := range []string{boxName, "GlobalSettings"} {
		ended := false
		for i := uint32(0); i < 1024; i++ {
			key, ok, err := r.query(section, "", i)
			if err != nil {
				return nil, err
			}
			if !ok {
				ended = true
				break
			}
			keys[key] = true
		}
		if !ended {
			return nil, errors.New("运行时设置枚举超限")
		}
	}
	values := map[string][]string{}
	for key := range keys {
		ended := false
		for i := uint32(0); i < 1024; i++ {
			value, ok, err := r.query(boxName, key, i)
			if err != nil {
				return nil, err
			}
			if !ok {
				ended = true
				break
			}
			values[key] = append(values[key], value)
		}
		if !ended {
			return nil, errors.New("运行时设置值枚举超限")
		}
	}
	return values, nil
}

func (r *installedRuntime) inspect(ctx context.Context) (Inspection, error) {
	report := Inspection{Signatures: r.signatures, State: "incomplete", RuntimeVersion: RuntimeVersion, Reason: "原生预览准备不完整；没有完整保护证明"}
	for _, target := range []string{"chrome", "edge", "claude"} {
		name, _ := box(target)
		values, err := r.effective(name)
		if err != nil {
			return report, err
		}
		if len(values["Enabled"]) == 0 {
			return report, fmt.Errorf("缺少分组：%s 尚未建立；请先运行包内第 2 步生成配置计划，审核后执行第 3 步", name)
		}
		if err := VerifyEffective(values); err != nil {
			return report, fmt.Errorf("%s: %w", name, err)
		}
		report.Boxes = append(report.Boxes, name)
	}
	filters, err := enforce.InspectSandboxie(ctx)
	report.Filters = filters
	if err != nil {
		return report, err
	}
	report.State = "preview-incomplete"
	report.Reason = "试用前置条件已核对；尚未完成 Windows 实机测试。断线、登录与更新仍需验证，当前不能宣称完整应用保护。"
	return report, nil
}

func inspect(ctx context.Context) (Inspection, error) {
	r, err := installed(ctx)
	if err != nil {
		report := Inspection{State: "unavailable", Reason: err.Error()}
		var signature *signatureError
		if errors.As(err, &signature) {
			report.Signatures = []SignatureEvidence{signature.Evidence}
		}
		return report, err
	}
	defer r.dll.Release()
	report, err := r.inspect(ctx)
	if err != nil {
		report.Reason = err.Error()
	}
	return report, err
}

func requireStopped(names ...string) error {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return errors.New("无法核对现有应用进程，不启动")
	}
	defer syscall.CloseHandle(handle)
	var p syscall.ProcessEntry32
	p.Size = uint32(unsafe.Sizeof(p))
	err = syscall.Process32First(handle, &p)
	for err == nil {
		for _, name := range names {
			if strings.EqualFold(syscall.UTF16ToString(p.ExeFile[:]), name) {
				return fmt.Errorf("%s 已在运行；请手动完全退出全部窗口及辅助进程，避免复用已有未验证进程", name)
			}
		}
		err = syscall.Process32Next(handle, &p)
	}
	if err != syscall.ERROR_NO_MORE_FILES {
		return errors.New("进程核对未完成，不启动")
	}
	return nil
}

func prepare(ctx context.Context, target, path string) (*exec.Cmd, error) {
	if _, ok := targets[target]; !ok {
		return nil, errors.New("不支持所选应用")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	profile := filepath.Join(dir, "ExitGuard", "NativeProfiles", target)
	plan, err := Command(target, path, profile)
	if err != nil {
		return nil, err
	}
	r, err := installed(ctx)
	if err != nil {
		return nil, err
	}
	defer r.dll.Release()
	if _, err := r.inspect(ctx); err != nil {
		return nil, err
	}
	if err := signedFile(ctx, path, target); err != nil {
		return nil, err
	}
	if err := requireStopped(targets[target]); err != nil {
		return nil, err
	}
	// Profile is new, product-owned and stays virtualized inside the box. Never
	// open the user's existing profile through a direct-access exception.
	return exec.Command(filepath.Join(r.home, "Start.exe"), plan.Args...), nil
}

func (r *installedRuntime) iniPath() (string, error) {
	location, ok, err := r.query("", "IniLocation", 0)
	if err != nil || !ok {
		return "", errors.New("无法定位驱动当前加载的 INI")
	}
	switch location {
	case "H":
		return filepath.Join(r.home, "Sandboxie.ini"), nil
	case "W":
		var b [32768]uint16
		n, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetWindowsDirectoryW").Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if n == 0 || n >= uintptr(len(b)) {
			return "", errors.New("无法定位系统 INI")
		}
		return filepath.Join(syscall.UTF16ToString(b[:n]), "Sandboxie.ini"), nil
	}
	if err := WindowsPath(location); err != nil {
		return "", err
	}
	return location, nil
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func stage(ctx context.Context) (string, []byte, error) {
	r, err := installed(ctx)
	if err != nil {
		return "", nil, err
	}
	defer r.dll.Release()
	if err := requireStopped("chrome.exe", "msedge.exe", "Claude.exe"); err != nil {
		return "", nil, err
	}
	path, err := r.iniPath()
	if err != nil {
		return "", nil, err
	}
	if err := regularLocal(path); err != nil {
		return "", nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", nil, errors.New("无法读取当前 INI")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return "", nil, errors.New("当前 INI 无法读取或超过 4MiB 限制")
	}
	if _, err := AppendOwnedBoxes(data); err != nil {
		return "", nil, err
	}
	return digest(data), Snippet(), nil
}
func apply(ctx context.Context, expectedHash string) error {
	if len(expectedHash) != 64 {
		return errors.New("apply 需要 stage 输出的当前配置 SHA-256")
	}
	r, err := installed(ctx)
	if err != nil {
		return err
	}
	defer r.dll.Release()
	if err := requireStopped("chrome.exe", "msedge.exe", "Claude.exe"); err != nil {
		return err
	}
	path, err := r.iniPath()
	if err != nil {
		return err
	}
	if err := regularLocal(path); err != nil {
		return err
	}
	utfPath, _ := syscall.UTF16PtrFromString(path)
	// share mode0 also excludes simultaneous replacement/deletion while appending.
	handle, err := syscall.CreateFile(utfPath, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return errors.New("无法独占打开 INI；请关闭 Sandboxie 配置编辑器，并仅对此步骤使用管理员权限")
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	old, err := io.ReadAll(io.LimitReader(file, 4<<20+1))
	if err != nil {
		return err
	}
	if digest(old) != strings.ToLower(expectedHash) {
		return errors.New("Sandboxie 配置已变化，请重新暂存并审核")
	}
	next, err := AppendOwnedBoxes(old)
	if err != nil {
		return err
	}
	backup, err := privateBackup(path + ".exitguard-" + expectedHash[:12] + ".bak")
	if err != nil {
		return errors.New("无法创建配置备份（可能已有同名备份），没有修改 INI")
	}
	_, writeErr := backup.Write(old)
	syncErr := backup.Sync()
	closeErr := backup.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("备份未完成，没有修改 INI")
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := file.Write(next[len(old):]); err != nil {
		_ = file.Truncate(int64(len(old)))
		return errors.New("追加失败，已尝试恢复原长度；请核对备份")
	}
	if err := file.Sync(); err != nil {
		return errors.New("配置同步失败，请核对备份；没有启动任何目标")
	}
	if err := file.Close(); err != nil {
		return err
	}
	code, err := r.call("SbieApi_ReloadConf", 0xffffffff, 1)
	if err != nil || code != 0 {
		return errors.New("分组已追加，但运行时重载失败；请在 Sandboxie 中重载配置后执行 native-inspect；尚未启动目标")
	}
	if _, err := r.inspect(ctx); err != nil {
		return fmt.Errorf("配置已追加但预览前置条件未通过：%w", err)
	}
	return nil
}

// Membership observes current kernel attribution through the documented API.
// The probe calls it inside the box, and records actual flags rather than
// accepting a caller-supplied 'boxed' boolean.
func Membership(ctx context.Context, pid uint32) (string, uint64, error) {
	r, err := installed(ctx)
	if err != nil {
		return "", 0, err
	}
	defer r.dll.Release()
	var name [34]uint16
	code, err := r.call("SbieApi_QueryProcess", uintptr(pid), uintptr(unsafe.Pointer(&name[0])), 0, 0, 0)
	if err != nil || code != 0 {
		return "", 0, errors.New("进程未获得驱动确认的箱归属")
	}
	flags, err := r.call("SbieApi_QueryProcessInfo", uintptr(pid), 0)
	if err != nil || flags&1 == 0 || flags&0x80000000 != 0 || flags&0x04000000 != 0 {
		return "", uint64(flags), errors.New("进程不是正常受限箱进程")
	}
	return syscall.UTF16ToString(name[:]), uint64(flags), nil
}
func probeCommand(ctx context.Context, target string) (*exec.Cmd, error) {
	name, err := box(target)
	if err != nil {
		return nil, err
	}
	r, err := installed(ctx)
	if err != nil {
		return nil, err
	}
	defer r.dll.Release()
	if _, err := r.inspect(ctx); err != nil {
		return nil, err
	}
	host, err := os.Executable()
	if err != nil {
		return nil, err
	}
	probe := filepath.Join(filepath.Dir(host), "ExitGuardNativeProbe.exe")
	if err := regularLocal(probe); err != nil {
		return nil, err
	}
	return exec.Command(filepath.Join(r.home, "Start.exe"), "/box:"+name, "/wait", probe, "--box", name), nil
}
func requireUnboxed(ctx context.Context) error {
	r, err := installed(ctx)
	if err != nil {
		return err
	}
	defer r.dll.Release()
	var name [34]uint16
	status, err := r.call("SbieApi_QueryProcess", uintptr(os.Getpid()), uintptr(unsafe.Pointer(&name[0])), 0, 0, 0)
	if !unboxedSelfQuery(status, err) {
		return errors.New("未能明确确认此进程在箱外；不能启动/标记箱外对照")
	}
	return nil
}

func targetsStopped() error { return requireStopped("chrome.exe", "msedge.exe", "Claude.exe") }
