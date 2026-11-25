//go:build exitguard_integration

package managedproxy

import (
	"context"
	"path/filepath"
)

// NewIntegrationFixtureManager is available only to explicitly tagged local
// integration tests. It keeps the official manifest/hash verification intact;
// the supplied resolver can pin only IPv4 loopback, never an Internet endpoint.
// Release/default builds exclude this entire file and API.
func NewIntegrationFixtureManager(opts Options, corePath, supervisorPath string, endpoint func(context.Context, string) (string, error)) *Manager {
	m := NewManager(opts)
	m.resolve = func() (bundle, error) {
		if filepath.Dir(corePath) != filepath.Dir(supervisorPath) {
			return bundle{}, ErrPackage
		}
		return bundle{supervisorPath, corePath, coreHash()}, nil
	}
	m.endpoint = func(ctx context.Context, host string) (string, error) {
		if endpoint == nil {
			return "", ErrNode
		}
		ip, err := endpoint(ctx, host)
		if err != nil || ip != "127.0.0.1" {
			return "", ErrNode
		}
		return ip, nil
	}
	return m
}
