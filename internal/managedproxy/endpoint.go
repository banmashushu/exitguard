package managedproxy

import (
	"context"
	"exitguard/internal/subscription"
	"net"
	"net/netip"
	"sort"
	"time"
)

// The core gets exactly one trusted hosts entry. The original hostname stays
// intact for TLS SNI and WS/gRPC authority; it never resolves that name again.
func resolveEndpoint(ctx context.Context, host string) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if publicIPv4(ip) {
			return ip.String(), nil
		}
		return "", ErrNode
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 || len(ips) > 32 {
		return "", ErrNode
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !publicIPv4(ip) {
			return "", ErrNode
		}
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out[0], nil
}
func publicIPv4(ip netip.Addr) bool { return subscription.PublicIPv4(ip) }
