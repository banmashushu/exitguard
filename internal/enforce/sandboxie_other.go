//go:build !windows || !amd64

package enforce

import (
	"context"
	"errors"
)

func inspectSandboxie(context.Context) ([]SandboxieFilter, error) {
	return nil, errors.New("原生应用预览仅支持 Windows x64")
}
