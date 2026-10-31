//go:build windows

package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// No profiles, execution-policy changes, user input, registry writes or service
// changes. The CIM module and PowerShell executable use the OS system directory.
// Each query is local, projects only allowed metadata, and fails to unknown.
const metadataScript = `
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Import-Module (Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
$r = @{version='';build='';bfe='unknown';elevated='unknown';apps=@();apps_known=$false}
try { $o = Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,BuildNumber; $r.version = [string]$o.Version; $r.build = [string]$o.BuildNumber } catch {}
try { $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='BFE'" -Property State; if ($s) { $r.bfe = [string]$s.State } } catch {}
try { $p = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { $r.elevated='yes' } else { $r.elevated='no' } } catch {}
try {
 $items = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='mihomo-party.exe' OR Name='Mihomo Party.exe' OR Name='clash-party.exe' OR Name='Clash Party.exe' OR Name='Claude.exe' OR Name='chrome.exe' OR Name='msedge.exe'" -Property Name,ExecutablePath | Select-Object Name,ExecutablePath -Unique | Select-Object -First 32)
 $r.apps = @($items | ForEach-Object { @{name=[string]$_.Name;path=[string]$_.ExecutablePath} })
 $r.apps_known=$true
} catch {}
$r | ConvertTo-Json -Depth 4 -Compress
`

func collectPlatform(ctx context.Context) platformData {
	data := platformData{Windows: unknownWindows("unknown")}
	if ctx.Err() != nil {
		return data
	}
	systemDir, err := windowsSystemDirectory()
	if err == nil {
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(queryCtx, filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", metadataScript)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Dir = systemDir
		cmd.WaitDelay = time.Second
		output := &boundedOutput{}
		cmd.Stdout, cmd.Stderr = output, io.Discard
		if err := cmd.Run(); err == nil {
			if parsed, err := parseWindowsMetadata(bytes.TrimPrefix(output.Bytes(), []byte{0xef, 0xbb, 0xbf})); err == nil {
				data = parsed
			}
		}
	}
	// Profile strings are used only for redaction. Never inspect candidate files:
	// UNC roots, mapped drives or junctions could otherwise contact a remote share.
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		data.Homes = append(data.Homes, profile)
	}
	if home, err := os.UserHomeDir(); err == nil {
		data.Homes = append(data.Homes, home)
	}
	return data
}

func windowsSystemDirectory() (string, error) {
	var buffer [syscall.MAX_PATH + 1]uint16
	n, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return "", errors.New("system directory unavailable")
	}
	path := syscall.UTF16ToString(buffer[:n])
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return "", errors.New("system directory unavailable")
	}
	return path, nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > 64*1024-b.Len() {
		return 0, errors.New("metadata output too large")
	}
	return b.Buffer.Write(p)
}
