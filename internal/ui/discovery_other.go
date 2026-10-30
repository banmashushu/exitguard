//go:build !darwin

package ui

import (
	"context"
	"time"
)

const discoveryTimeout = 3 * time.Second

func installedDesktopApplications(context.Context) []desktopApplication {
	return []desktopApplication{}
}
