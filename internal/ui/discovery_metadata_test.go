package ui

import (
	"strings"
	"testing"
)

func TestClaudeInventoryAcceptsOnlyExactNamedBoundedLocalPackages(t *testing.T) {
	data := []byte(`[{"Name":"Claude","InstallLocation":"C:\\Program Files\\WindowsApps\\Claude_1_x64"},{"Name":"OtherClaude","InstallLocation":"C:\\Other"},{"Name":"Claude","InstallLocation":"\\\\server\\Claude"}]`)
	got := claudePackageLocations(data)
	if len(got) != 1 || got[0] != `C:\Program Files\WindowsApps\Claude_1_x64` {
		t.Fatalf("unexpected package roots: %v", got)
	}
	if got := claudePackageLocations([]byte(strings.Repeat(" ", maxWindowsDiscoveryOutput+1))); len(got) != 0 {
		t.Fatal("unbounded package output accepted")
	}
}

func TestClaudeManifestSuppliesOnlyContainedClaudeExecutables(t *testing.T) {
	manifest := []byte(`<Package xmlns="urn:appx"><Identity Name="Claude"/><Applications>
<Application Id="Desktop" Executable="app\Claude.exe"/>
<Application Executable="..\outside\Claude.exe"/><Application Executable="C:\outside\Claude.exe"/>
<Application Executable="app\Helper.exe"/><Application Executable="app\Claude.exe:stream"/>
<Application Executable="app/Claude.exe"/>
</Applications></Package>`)
	got := claudeManifestExecutables(manifest)
	if len(got) != 1 || got[0] != `app\Claude.exe` {
		t.Fatalf("unsafe or invented package executables: %v", got)
	}
	for _, invalid := range [][]byte{[]byte(`<Package><Identity Name="NotClaude"/><Applications><Application Executable="Claude.exe"/></Applications></Package>`), []byte(`<Package`), make([]byte, maxWindowsManifest+1)} {
		if got := claudeManifestExecutables(invalid); len(got) != 0 {
			t.Fatal("invalid manifest accepted")
		}
	}
}

func TestWindowsInventoryRejectsNetworkDeviceADSAndRelativePaths(t *testing.T) {
	for _, path := range []string{`\\server\share\Claude.exe`, `\\?\C:\Claude.exe`, `\\.\pipe\Claude.exe`, `C:Claude.exe`, `\Claude.exe`, `C:\Claude.exe:stream`, `C:\apps\..\Claude.exe`, `C:\apps\Claude.exe `, `C:\NUL\Claude.exe`} {
		if windowsInventoryLocalPath(path) {
			t.Fatalf("unsafe inventory path accepted: %q", path)
		}
	}
	if !windowsInventoryLocalPath(`C:\Program Files\Claude\Claude.exe`) {
		t.Fatal("ordinary drive path rejected")
	}
}
