package guard

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"exitguard/internal/model"
)

func TestTwoHopVerificationHasTimeForBothProxyConnections(t *testing.T) {
	for _, tc := range []struct {
		name, firstHop  string
		startup, health time.Duration
	}{
		{"single-hop", "", 15 * time.Second, 8 * time.Second},
		{"two-hop", "http://127.0.0.1:18080", 20 * time.Second, 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(filepath.Join(t.TempDir(), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			c := s.Config()
			c.Mode, c.EnforcementMode = "remote", "proxy-only"
			c.ProxyURL, c.PreProxyURL = "socks5://fixed.example:443", tc.firstHop
			c.ExpectedIPs = []string{"203.0.113.7"}
			if err = s.SaveConfig(c); err != nil {
				t.Fatal(err)
			}
			defer s.Disarm()
			var remaining time.Duration
			r := &diagnosticProbeRoute{probe: func(ctx context.Context) (string, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Error("verification has no deadline")
				}
				remaining = time.Until(deadline)
				return "203.0.113.7", nil
			}}
			s.makeRemoteRoute = func(context.Context, model.Config, string, string) (route, error) { return r, nil }
			s.makeChainedRemoteRoute = func(context.Context, model.Config, string, string, string, string) (route, error) { return r, nil }
			if err := s.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			if remaining > tc.startup || remaining < tc.startup-time.Second {
				t.Fatalf("startup verification budget is %s, want about %s", remaining, tc.startup)
			}
			s.mu.Lock()
			s.status.State = "proxy_active"
			s.mu.Unlock()
			s.health(context.Background())
			if remaining > tc.health || remaining < tc.health-time.Second {
				t.Fatalf("health verification budget is %s, want about %s", remaining, tc.health)
			}
		})
	}
}
