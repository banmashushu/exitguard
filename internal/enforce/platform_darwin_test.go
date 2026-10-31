//go:build darwin

package enforce

import (
	"context"
	"testing"
)

func TestUnsignedMacBuildCannotClaimFilterProtection(t *testing.T) {
	if signingTeamID != "" {
		t.Skip("signed deployment build has a pinned team")
	}
	if Supported() {
		t.Fatal("ordinary local build reported trusted native deployment")
	}
	proof, err := Inspect(context.Background(), Policy{Port: 17890, Programs: []string{"/bin/sh"}})
	if err == nil || proof.Active || proof.PolicyHash != "" {
		t.Fatalf("unsigned build produced proof: %#v %v", proof, err)
	}
}
