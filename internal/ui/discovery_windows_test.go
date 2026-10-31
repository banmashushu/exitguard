package ui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsDiscoveryAcceptsLocalRegularFilesAndRejectsReparsePaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Claude.exe")
	if err := os.WriteFile(path, []byte("fixture only; never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	if !safeWindowsInventoryPath(path, false) || !safeWindowsInventoryPath(root, true) {
		t.Fatal("local regular inventory fixture rejected")
	}
	if safeWindowsInventoryPath(root, false) || safeWindowsInventoryPath(path, true) {
		t.Fatal("file/directory type mismatch accepted")
	}
	if safeWindowsInventoryPath(`\\server\share\Claude.exe`, false) || safeWindowsInventoryPath(path+":stream", false) {
		t.Fatal("remote or alternate stream inventory accepted")
	}
	link := filepath.Join(root, "linked.exe")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("Windows symlink creation unavailable; reparse runtime check remains required")
	}
	if safeWindowsInventoryPath(link, false) {
		t.Fatal("reparse executable listed")
	}
	parent := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(root, parent); err != nil {
		t.Fatal(err)
	}
	if safeWindowsInventoryPath(filepath.Join(parent, "Claude.exe"), false) {
		t.Fatal("reparse ancestor listed")
	}
}

func TestWindowsDiscoveryReadsOnlyBoundedOrdinaryManifestFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "AppxManifest.xml")
	manifest := `<Package><Identity Name="Claude"/><Applications><Application Executable="app\Claude.exe"/></Applications></Package>`
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	got := claudeManifestExecutables(windowsClaudeManifest(path))
	if len(got) != 1 || got[0] != `app\Claude.exe` {
		t.Fatal("ordinary package manifest unreadable")
	}
	if err := os.WriteFile(path, make([]byte, maxWindowsManifest+1), 0600); err != nil {
		t.Fatal(err)
	}
	if len(windowsClaudeManifest(path)) != 0 {
		t.Fatal("oversized manifest read")
	}
}
