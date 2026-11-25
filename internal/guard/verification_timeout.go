package guard

import (
	"context"
	"time"

	"exitguard/internal/model"
)

type verificationLimits struct {
	manual, health, dns, http time.Duration
	proxyHandshake            time.Duration
}

func limitsForRoute(chained bool) verificationLimits {
	if chained {
		// Outlet verification opens two tunnels: one to the DNS resolver,
		// then another to the IP probe. Budget for both on the chained path.
		return verificationLimits{manual: 20 * time.Second, health: 15 * time.Second, dns: 12 * time.Second, http: 20 * time.Second, proxyHandshake: 12 * time.Second}
	}
	return verificationLimits{manual: 15 * time.Second, health: 8 * time.Second, dns: 8 * time.Second, http: 10 * time.Second, proxyHandshake: 8 * time.Second}
}

func limitsForConfig(c model.Config) verificationLimits {
	return limitsForRoute(c.Mode == "remote" && (c.PreProxyURL != "" || c.ManagedSubscriptionID != ""))
}

// Only outlet probes attach this marker. Ordinary forwarding keeps its own
// request limits even when its route has a first hop.
type chainedVerificationKey struct{}

func limitsForProbe(ctx context.Context) verificationLimits {
	chained, _ := ctx.Value(chainedVerificationKey{}).(bool)
	return limitsForRoute(chained)
}
