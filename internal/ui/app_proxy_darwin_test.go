package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRemoveClaudeProxyPreferencesPreservesOtherSettingsAndCanRetry(t *testing.T) {
	const fixed = `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`
	const pac = `<key>egressProxyPacUrl</key><string>https://proxy.example.test/config.pac</string>`
	const other = `<key>disableAutoUpdates</key><true/><key>lastUpdated</key><date>2026-11-25T02:00:00Z</date>`
	paths := proxyPreferencesFixture(t, fixed+pac+other, fixed+other)
	if err := exec.Command("/usr/bin/plutil", "-convert", "binary1", "--", paths[1]).Run(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	apply := func(ctx context.Context, removals []claudeProxyKeyRemoval) error {
		for _, removal := range removals {
			if err := exec.CommandContext(ctx, "/usr/bin/plutil", "-remove", removal.key, "--", removal.path).Run(); err != nil {
				return err
			}
		}
		return nil
	}
	changed, err := removeClaudeProxyPreferences(ctx, paths, apply)
	if err != nil || !changed {
		t.Fatalf("remove proxy: changed=%v err=%v", changed, err)
	}
	for _, path := range paths {
		wanted := map[string]string{"disableAutoUpdates": "true", "lastUpdated": "2026-11-25T02:00:00Z"}
		for key, value := range wanted {
			got, err := exec.Command("/usr/bin/plutil", "-extract", key, "raw", "-o", "-", "--", path).Output()
			if err != nil || strings.TrimSpace(string(got)) != value {
				t.Fatalf("unrelated key %s in %s: got %q, err %v", key, path, got, err)
			}
		}
	}
	changed, err = removeClaudeProxyPreferences(ctx, paths, func(context.Context, []claudeProxyKeyRemoval) error {
		t.Fatal("requested write after all proxy keys were removed")
		return nil
	})
	if err != nil || changed {
		t.Fatalf("repeat removal: changed=%v err=%v", changed, err)
	}
}

func TestRemoveClaudeProxyPreferencesRejectsUnreadableScopeBeforeApplying(t *testing.T) {
	paths := proxyPreferencesFixture(t, `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`, "")
	if err := os.WriteFile(paths[1], []byte("invalid plist"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := removeClaudeProxyPreferences(context.Background(), paths, func(context.Context, []claudeProxyKeyRemoval) error {
		t.Fatal("requested write even though one preference scope was unreadable")
		return nil
	})
	if err == nil || changed {
		t.Fatalf("expected read failure: changed=%v err=%v", changed, err)
	}
}

func TestRemoveClaudeProxyPreferencesVerifiesRemoval(t *testing.T) {
	paths := proxyPreferencesFixture(t, "", `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`)
	changed, err := removeClaudeProxyPreferences(context.Background(), paths, func(context.Context, []claudeProxyKeyRemoval) error {
		return nil
	})
	if err == nil || changed {
		t.Fatalf("configuration still contains a proxy key: changed=%v err=%v", changed, err)
	}
}

func TestMacChromeWithoutProxyUsesDefaultProfileAndExplicitDirectSwitch(t *testing.T) {
	chrome := desktopFixture(t, t.TempDir(), "Google Chrome.app", "com.google.Chrome", "Google Chrome")
	ctx := context.Background()
	cmd, err := macChromeWithoutProxyCommand(ctx, chrome)
	if err != nil {
		t.Fatal(err)
	}
	app := filepath.Dir(filepath.Dir(filepath.Dir(chrome)))
	want := []string{"/usr/bin/open", "-a", app, "--args", "--no-proxy-server"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatalf("Chrome command = %q, want %q", cmd.Args, want)
	}

	edge := desktopFixture(t, t.TempDir(), "Microsoft Edge.app", "com.microsoft.edgemac", "Microsoft Edge")
	if _, err := macChromeWithoutProxyCommand(ctx, edge); err == nil {
		t.Fatal("accepted a non-Chrome target")
	}
}

func proxyPreferencesFixture(t *testing.T, entries ...string) []string {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, len(entries))
	for i, entry := range entries {
		path := filepath.Join(dir, fmt.Sprintf("preferences-%d.plist", i))
		paths[i] = path
		if entry != "" {
			plist := `<?xml version="1.0"?><plist version="1.0"><dict>` + entry + `</dict></plist>`
			if err := os.WriteFile(path, []byte(plist), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return paths
}
