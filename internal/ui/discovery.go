package ui

import "context"

// Application choices are inventory, never a claim about OS policy coverage.
type desktopApplication struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	BundleID string `json:"bundleID"`
}

func discoverApplications() []desktopApplication {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	return installedDesktopApplications(ctx)
}
