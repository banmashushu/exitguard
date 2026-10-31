package guard

import (
	"context"
	"path/filepath"
	"testing"
)

// A queued native action can reach the service after Pause canceled its context.
// Such an action must not change a stopped session even briefly.
func TestCanceledActionDoesNotReplacePausedState(t *testing.T) {
	for _, action := range []string{"check", "arm", "candidate"} {
		t.Run(action, func(t *testing.T) {
			s, err := New(filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			s.Disarm()
			before := s.Status()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			switch action {
			case "check":
				err = s.Check(ctx)
			case "arm":
				err = s.Arm(ctx)
			case "candidate":
				_, err = s.ProbeCandidate(ctx)
			}
			if err == nil {
				t.Fatal("canceled action succeeded")
			}
			if got := s.Status(); got.State != "stopped" || got.SessionRevision != before.SessionRevision {
				t.Fatalf("canceled action replaced pause: %+v", got)
			}
		})
	}
}
