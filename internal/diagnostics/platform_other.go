//go:build !windows

package diagnostics

import "context"

func collectPlatform(context.Context) platformData {
	return platformData{Windows: unknownWindows("unsupported")}
}
