package ui

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const discoveryTimeout = 3 * time.Second

var (
	discoveryKernel32        = syscall.NewLazyDLL("kernel32.dll")
	discoveryShell32         = syscall.NewLazyDLL("shell32.dll")
	discoveryOle32           = syscall.NewLazyDLL("ole32.dll")
	discoveryKnownFolder     = discoveryShell32.NewProc("SHGetKnownFolderPath")
	discoveryFree            = discoveryOle32.NewProc("CoTaskMemFree")
	discoveryDriveType       = discoveryKernel32.NewProc("GetDriveTypeW")
	discoverySystemDirectory = discoveryKernel32.NewProc("GetSystemDirectoryW")
)

type windowsApplicationSpec struct{ executable, kind, name string }

var windowsApplicationSpecs = []windowsApplicationSpec{
	{"chrome.exe", "browser", "Chrome"},
	{"msedge.exe", "browser", "Edge"},
	{"Claude.exe", "claude", "Claude Desktop"},
}

func installedDesktopApplications(ctx context.Context) []desktopApplication {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	apps := make([]desktopApplication, 0, 8)
	seen := make(map[string]bool)
	add := func(path string, spec windowsApplicationSpec) {
		if ctx.Err() != nil || !strings.EqualFold(filepath.Base(path), spec.executable) || !safeWindowsInventoryPath(path, false) {
			return
		}
		canonical, err := canonicalExecutable(path, "windows")
		if err != nil || !strings.EqualFold(canonical, filepath.Clean(path)) || seen[strings.ToLower(canonical)] {
			return
		}
		seen[strings.ToLower(canonical)] = true
		apps = append(apps, desktopApplication{Kind: spec.kind, Name: spec.name, Path: canonical})
	}
	// Read the default value of three exact App Paths keys, in both registry
	// views. Never enumerate installed software or search a user's PATH/profile.
	for _, spec := range windowsApplicationSpecs {
		for _, hive := range []syscall.Handle{syscall.HKEY_CURRENT_USER, syscall.HKEY_LOCAL_MACHINE} {
			for _, view := range []uint32{0x100, 0x200} {
				if ctx.Err() != nil {
					return apps
				}
				if path := windowsAppPath(hive, view, spec.executable); path != "" {
					add(path, spec)
				}
			}
		}
	}
	// Known Folder identities come from Windows, never an environment variable.
	// Only fixed Chrome/Edge installation candidates are probed. Current Claude
	// MSIX installs are obtained from their manifest below, with no guessed path.
	for _, id := range []syscall.GUID{
		{Data1: 0xF1B32785, Data2: 0x6FBA, Data3: 0x4FCF, Data4: [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}},
		{Data1: 0x905e63b6, Data2: 0xc1bf, Data3: 0x494e, Data4: [8]byte{0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a}},
		{Data1: 0x7c5a40ef, Data2: 0xa0fb, Data3: 0x4bfc, Data4: [8]byte{0x87, 0x4a, 0xc0, 0xf2, 0xe0, 0xb9, 0xfa, 0x8e}},
	} {
		if ctx.Err() != nil {
			return apps
		}
		root := windowsKnownFolder(id)
		if root == "" {
			continue
		}
		add(filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"), windowsApplicationSpecs[0])
		add(filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"), windowsApplicationSpecs[1])
	}
	for _, root := range windowsClaudePackages(ctx) {
		if ctx.Err() != nil {
			return apps
		}
		data := windowsClaudeManifest(filepath.Join(root, "AppxManifest.xml"))
		for _, relative := range claudeManifestExecutables(data) {
			path := filepath.Join(root, relative)
			rel, err := filepath.Rel(root, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, `..\`) && !filepath.IsAbs(rel) {
				spec := windowsApplicationSpecs[2]
				spec.name = "Claude Desktop（MSIX，需验证）"
				add(path, spec)
			}
		}
	}
	return apps
}

func windowsAppPath(hive syscall.Handle, view uint32, executable string) string {
	key, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\App Paths\` + executable)
	var handle syscall.Handle
	if syscall.RegOpenKeyEx(hive, key, 0, syscall.KEY_QUERY_VALUE|view, &handle) != nil {
		return ""
	}
	defer syscall.RegCloseKey(handle)
	var kind, size uint32
	if syscall.RegQueryValueEx(handle, nil, nil, &kind, nil, &size) != nil || kind != syscall.REG_SZ || size < 2 || size > 16<<10 || size%2 != 0 {
		return ""
	}
	buffer := make([]uint16, size/2)
	if syscall.RegQueryValueEx(handle, nil, nil, &kind, (*byte)(unsafe.Pointer(&buffer[0])), &size) != nil || kind != syscall.REG_SZ || size < 2 || size > uint32(len(buffer)*2) || size%2 != 0 {
		return ""
	}
	buffer = buffer[:size/2]
	if buffer[len(buffer)-1] != 0 {
		return ""
	}
	for _, char := range buffer[:len(buffer)-1] {
		if char == 0 {
			return ""
		}
	}
	path := syscall.UTF16ToString(buffer)
	if len(path) >= 2 && path[0] == '"' && path[len(path)-1] == '"' {
		path = path[1 : len(path)-1]
	}
	if !windowsInventoryLocalPath(path) {
		return ""
	}
	return path
}

func windowsKnownFolder(id syscall.GUID) string {
	var text *uint16
	hr, _, _ := discoveryKnownFolder.Call(uintptr(unsafe.Pointer(&id)), 0, 0, uintptr(unsafe.Pointer(&text)))
	if hr != 0 || text == nil {
		return ""
	}
	defer discoveryFree.Call(uintptr(unsafe.Pointer(text)))
	path := windowsDiscoveryString(text, 32768)
	if !windowsInventoryLocalPath(path) {
		return ""
	}
	return path
}

func windowsDiscoveryString(text *uint16, limit int) string {
	var data []uint16
	for i := 0; i < limit; i++ {
		v := *(*uint16)(unsafe.Add(unsafe.Pointer(text), i*2))
		if v == 0 {
			return syscall.UTF16ToString(data)
		}
		data = append(data, v)
	}
	return ""
}

func safeWindowsInventoryPath(path string, directory bool) bool {
	if !windowsInventoryLocalPath(path) {
		return false
	}
	root, _ := syscall.UTF16PtrFromString(path[:3])
	drive, _, _ := discoveryDriveType.Call(uintptr(unsafe.Pointer(root)))
	if drive != 3 {
		return false
	}
	current := path[:3]
	parts := strings.Split(path[3:], `\`)
	for i, part := range parts {
		current = filepath.Join(current, part)
		p, _ := syscall.UTF16PtrFromString(current)
		attrs, err := syscall.GetFileAttributes(p)
		if err != nil || attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		wantDir := i < len(parts)-1 || directory
		if (attrs&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != wantDir {
			return false
		}
	}
	info, err := os.Lstat(path)
	return err == nil && (directory && info.IsDir() || !directory && info.Mode().IsRegular())
}

func windowsClaudePackages(ctx context.Context) []string {
	if ctx.Err() != nil {
		return nil
	}
	buffer := make([]uint16, 32768)
	n, _, _ := discoverySystemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return nil
	}
	system := syscall.UTF16ToString(buffer[:n])
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	if !safeWindowsInventoryPath(powershell, false) {
		return nil
	}
	// Fixed command, exact current-user package name, no wildcard/all-users,
	// shell profile, launch, configuration read or arbitrary command arguments.
	const query = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $p=@(Get-AppxPackage -Name Claude | Where-Object { $_.Name -eq 'Claude' } | Select-Object -First 4 Name,InstallLocation); ConvertTo-Json -InputObject $p -Compress`
	cmd := exec.CommandContext(ctx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Restrict auto-loaded PowerShell modules to the OS module directory.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToLower(entry), "psmodulepath=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "PSModulePath="+filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules"))
	var out boundedWindowsDiscovery
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if cmd.Run() != nil {
		return nil
	}
	return claudePackageLocations(out.Bytes())
}

func windowsClaudeManifest(path string) []byte {
	if !safeWindowsInventoryPath(path, false) {
		return nil
	}
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var byHandle syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(h, &byHandle) != nil || byHandle.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxWindowsManifest {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxWindowsManifest+1))
	if err != nil || len(data) > maxWindowsManifest {
		return nil
	}
	return data
}
