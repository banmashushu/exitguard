package enforce

import "testing"

// An intent-only flag, dormant callout or conditional filter must never suffice.
func TestSandboxieRuntimeRequiresRegisteredCalloutsAndFourExactFilters(t *testing.T) {
	observations := []SandboxieFilter{}
	for _, layer := range []string{"connect4", "connect6", "accept4", "accept6"} {
		observations = append(observations, SandboxieFilter{Layer: layer, Registered: true, Exact: true})
	}
	if err := validateSandboxieRuntime(observations); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]SandboxieFilter{nil, observations[:3], append(append([]SandboxieFilter{}, observations...), observations[0]), {{Layer: "connect4", Registered: false, Exact: true}, {Layer: "connect6", Registered: true, Exact: true}, {Layer: "accept4", Registered: true, Exact: true}, {Layer: "accept6", Registered: true, Exact: true}}, {{Layer: "connect4", Registered: true, Exact: false}, {Layer: "connect6", Registered: true, Exact: true}, {Layer: "accept4", Registered: true, Exact: true}, {Layer: "accept6", Registered: true, Exact: true}}} {
		if validateSandboxieRuntime(bad) == nil {
			t.Fatal("accepted incomplete kernel evidence")
		}
	}
}
