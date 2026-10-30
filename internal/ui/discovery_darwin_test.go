package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func desktopFixture(t *testing.T, root, name, id, executable string) string {
	t.Helper()
	root, _ = filepath.EvalSymlinks(root)
	bundle := filepath.Join(root, name)
	contents := filepath.Join(bundle, "Contents")
	macOS := filepath.Join(contents, "MacOS")
	if err := os.MkdirAll(macOS, 0700); err != nil {
		t.Fatal(err)
	}
	plist := fmt.Sprintf(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>%s</string><key>CFBundleExecutable</key><string>%s</string></dict></plist>`, id, executable)
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(macOS, executable)
	if err := os.WriteFile(path, []byte("not executed"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestMacDiscoveryUsesKnownBundlesAndTheirIdentities(t *testing.T) {
	root := t.TempDir()
	user := t.TempDir()
	chrome := desktopFixture(t, root, "Google Chrome.app", "com.google.Chrome", "Google Chrome")
	claude := desktopFixture(t, user, "Claude.app", "com.anthropic.claudefordesktop", "Claude")
	desktopFixture(t, root, "Microsoft Edge.app", "com.anthropic.claude-code-url-handler", "Microsoft Edge")
	desktopFixture(t, root, "Claude Code URL Handler.app", "com.anthropic.claude-code-url-handler", "claude")
	desktopFixture(t, root, "Claude Code.app", "com.anthropic.claudefordesktop", "claude")
	desktopFixture(t, root, "Chromium.app", "org.chromium.Chromium", "Chromium")
	apps := discoverMacApplications(context.Background(), []string{root, user})
	if len(apps) != 2 {
		t.Fatalf("want supported desktop bundles only, got %+v", apps)
	}
	if apps[0].Kind != "browser" || apps[0].Name != "Chrome" || apps[0].Path != chrome || apps[1].Kind != "claude" || apps[1].Name != "Claude Desktop / Code" || apps[1].Path != claude {
		t.Fatalf("wrong application identities: %+v", apps)
	}
	if b, err := os.ReadFile(chrome); err != nil || string(b) != "not executed" {
		t.Fatal("discovery changed executable")
	}
}
func TestMacDiscoveryRejectsMissingNonExecutableEscapingAndMalformedBundles(t *testing.T) {
	for _, kind := range []string{"missing", "nonexecutable", "wrong-id", "bad-executable", "oversize", "symlink-outside"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := desktopFixture(t, root, "Claude.app", "com.anthropic.claudefordesktop", "Claude")
			plist := filepath.Join(root, "Claude.app", "Contents", "Info.plist")
			var err error
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "nonexecutable":
				err = os.Chmod(path, 0600)
			case "wrong-id":
				err = os.WriteFile(plist, []byte(`<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>handler</string><key>CFBundleExecutable</key><string>Claude</string></dict></plist>`), 0600)
			case "bad-executable":
				err = os.WriteFile(plist, []byte(`<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>../../elsewhere</string></dict></plist>`), 0600)
			case "oversize":
				err = os.WriteFile(plist, make([]byte, 128<<10+1), 0600)
			case "symlink-outside":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "Claude")
				if err = os.WriteFile(outside, []byte("do not run"), 0700); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(outside, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if apps := discoverMacApplications(context.Background(), []string{root}); len(apps) != 0 {
				t.Fatalf("unsafe bundle listed: %+v", apps)
			}
		})
	}
}
func TestMacDiscoveryReadsBinaryPlistsAndDeduplicatesResolvedTargets(t *testing.T) {
	root := t.TempDir()
	path := desktopFixture(t, root, "Claude.app", "com.anthropic.claudefordesktop", "Claude")
	plist := filepath.Join(root, "Claude.app", "Contents", "Info.plist")
	if err := exec.Command("/usr/bin/plutil", "-convert", "binary1", "--", plist).Run(); err != nil {
		t.Fatal(err)
	}
	apps := discoverMacApplications(context.Background(), []string{root, root})
	if len(apps) != 1 || apps[0].Path != path {
		t.Fatalf("binary plist discovery or deduplication failed: %+v", apps)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if apps := discoverMacApplications(ctx, []string{root}); len(apps) != 0 {
		t.Fatal("cancelled discovery continued")
	}
}

func TestMacDiscoveryRejectsLinkedInstalledBundleAndContents(t *testing.T) {
	for _, link := range []string{"bundle", "Contents", "MacOS"} {
		t.Run(link, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			desktopFixture(t, outside, "Claude.app", "com.anthropic.claudefordesktop", "Claude")
			bundle := filepath.Join(root, "Claude.app")
			source := filepath.Join(outside, "Claude.app")
			switch link {
			case "Contents":
				if err := os.Mkdir(bundle, 0700); err != nil {
					t.Fatal(err)
				}
				bundle = filepath.Join(bundle, "Contents")
				source = filepath.Join(source, "Contents")
			case "MacOS":
				if err := os.MkdirAll(filepath.Join(bundle, "Contents"), 0700); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(source, "Contents", "Info.plist"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(bundle, "Contents", "Info.plist"), data, 0600); err != nil {
					t.Fatal(err)
				}
				bundle = filepath.Join(bundle, "Contents", "MacOS")
				source = filepath.Join(source, "Contents", "MacOS")
			}
			if err := os.Symlink(source, bundle); err != nil {
				t.Fatal(err)
			}
			if apps := discoverMacApplications(context.Background(), []string{root}); len(apps) != 0 {
				t.Fatal("linked installed bundle was followed and listed")
			}
		})
	}
}
