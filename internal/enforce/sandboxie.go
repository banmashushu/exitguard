package enforce

import (
	"context"
	"errors"
)

type SandboxieFilter struct {
	Layer      string `json:"layer"`
	Registered bool   `json:"registered"`
	Exact      bool   `json:"exactFilter"`
}

func validateSandboxieRuntime(filters []SandboxieFilter) error {
	expected := map[string]bool{"connect4": true, "connect6": true, "accept4": true, "accept6": true}
	for _, f := range filters {
		if !expected[f.Layer] || !f.Registered || !f.Exact {
			return errors.New("Sandboxie WFP 回调或过滤规则缺失、未注册或发生变化")
		}
		delete(expected, f.Layer)
	}
	if len(expected) != 0 {
		return errors.New("Sandboxie 的四个 WFP 回调与过滤规则尚未全部核验")
	}
	return nil
}

// InspectSandboxie is read-only; it checks current BFE objects and kernel
// registration, not Sandboxie's intent-only driver feature bit.
func InspectSandboxie(ctx context.Context) ([]SandboxieFilter, error) { return inspectSandboxie(ctx) }
