//go:build windows

package diagnostics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsDiscoveryIgnoresFilesInEnvironmentRoots(t *testing.T) {
	root := t.TempDir()
	// Harmless local stand-ins for the former candidate scan. No executable is run.
	for _, suffix := range []string{`Programs\Claude\Claude.exe`, `Google\Chrome\Application\chrome.exe`, `Programs\Clash Party\Clash Party.exe`} {
		path := filepath.Join(root, suffix)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("not an executable"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LOCALAPPDATA", root)
	t.Setenv("ProgramFiles", root)
	t.Setenv("ProgramFiles(x86)", root)
	data := collectPlatform(context.Background())
	for _, app := range data.Apps {
		relative, err := filepath.Rel(root, app.Path)
		if err == nil && relative != ".." && !filepath.IsAbs(relative) && len(relative) > 0 && relative[0] != '.' {
			t.Fatalf("unopened file reported as running process: %+v", app)
		}
	}
}
