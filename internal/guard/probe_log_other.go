//go:build !windows

package guard

func probeLogDirectory(path string) (string, error) { return credentialDirectory(path, true) }
