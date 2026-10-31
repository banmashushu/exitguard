package enforce

import (
	"strings"
	"testing"
)

func TestMacManagerProofRequiresExactPolicyAndHealthyProvider(t *testing.T) {
	hash := strings.Repeat("a", 64)
	tests := []struct {
		data string
		want bool
	}{
		{`{"active":true,"policyHash":"` + hash + `","reason":"running"}`, true},
		{`{"active":true,"policyHash":"` + strings.Repeat("b", 64) + `","reason":"running"}`, false},
		{`{"active":false,"policyHash":"` + hash + `","reason":"provider unavailable"}`, false},
		{`{"active":true,"policyHash":"` + hash + `","extra":"untrusted"}`, false},
		{`{"active":true,"policyHash":"` + hash + `"} {"active":false}`, false},
		{`{"active":true}`, false},
	}
	for _, tt := range tests {
		proof, err := parseManagerProof([]byte(tt.data), hash)
		if (err == nil && proof.Active) != tt.want {
			t.Errorf("accepted=%v for %s: %v", err == nil && proof.Active, tt.data, err)
		}
	}
}
