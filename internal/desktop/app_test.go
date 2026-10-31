package desktop

import (
	"path/filepath"
	"testing"
)

func TestDesktopRejectsLegacyCommandsInsteadOfLaunchingAnUnexpectedMode(t *testing.T) {
	for _, args := range [][]string{{"serve"}, {"native-console"}, {"--no-open"}, {"--config", ""}} {
		if _, err := configPath(args); err == nil {
			t.Fatalf("accepted legacy desktop arguments: %q", args)
		}
	}
	path := filepath.Join(t.TempDir(), "explicit.json")
	if got, err := configPath([]string{"--config", path}); err != nil || got != path {
		t.Fatalf("explicit config path %q: %v", got, err)
	}
}
