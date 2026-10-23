package enforce

import (
	"context"
	"testing"
)

func TestPolicyHashCanonicalAndSensitive(t *testing.T) {
	p := Policy{Port: 17890, Programs: []string{"/Applications/A.app/A", "/Applications/B.app/B"}, BundleIDs: []string{"com.example.A"}}
	q := Policy{Port: 17890, Programs: []string{"/Applications/B.app/B", "/Applications/A.app/A", "/Applications/A.app/A"}, BundleIDs: []string{"com.example.A", "com.example.A"}}
	if Hash(p) == "" || Hash(p) != Hash(q) {
		t.Fatal("duplicates/order changed equivalent policy")
	}
	q.Programs[0] = "/applications/B.app/B"
	if Hash(p) == Hash(q) {
		t.Fatal("case-sensitive executable path change was lost")
	}
	q = p
	q.Port++
	if Hash(p) == Hash(q) {
		t.Fatal("proxy port change did not invalidate proof")
	}
	q = p
	q.BundleIDs = []string{"com.example.B"}
	if Hash(p) == Hash(q) {
		t.Fatal("identity change did not invalidate proof")
	}
}

func TestInvalidPolicyCannotProduceProof(t *testing.T) {
	for _, p := range []Policy{
		{Port: 0, Programs: []string{"/bin/example"}},
		{Port: 17890},
		{Port: 17890, Programs: []string{"relative/path"}},
		{Port: 17890, Programs: []string{"/bin/example\x00other"}},
		{Port: 17890, BundleIDs: []string{"bad id"}},
	} {
		if Hash(p) != "" {
			t.Errorf("invalid policy hashed: %#v", p)
		}
		proof, err := Inspect(context.Background(), p)
		if err == nil || proof.Active {
			t.Errorf("invalid policy accepted: %#v: %#v %v", p, proof, err)
		}
	}
}

func TestPolicyHashDoesNotMutateInputs(t *testing.T) {
	p := Policy{Port: 17890, Programs: []string{"/z", "/a"}}
	Hash(p)
	if p.Programs[0] != "/z" {
		t.Fatal("hash sorted caller's policy")
	}
}
