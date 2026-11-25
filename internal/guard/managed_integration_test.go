//go:build exitguard_integration

package guard

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"exitguard/internal/managedproxy"
)

// The only core-path/endpoint injection is in this explicit integration build.
// Production still verifies and locates only the packaged official core.
func TestRealManagedCoreThroughGuardFixedFinalDoHAndForwarding(t *testing.T) {
	requireCredentialPersistence(t)
	core, e := filepath.Abs(filepath.Join("..", "..", ".work", "managed-stage-mac", "Helpers", "mihomo"))
	if e != nil {
		t.Fatal(e)
	}
	helper := filepath.Join(filepath.Dir(core), "exitguard-proxy-supervisor")
	if _, e = os.Stat(core); e != nil {
		t.Fatal("stage the pinned integration core before running this build-tag test")
	}
	manager := managedproxy.NewIntegrationFixtureManager(managedproxy.Options{RuntimeDir: filepath.Join(t.TempDir(), "private.managed")}, core, helper, func(context.Context, string) (string, error) { return "127.0.0.1", nil })
	defer manager.Stop()
	exerciseRemoteProxyOnlyForwardingManaged(t, true, &ownedManagedController{manager: manager})
}
