package nativeapp

import (
	"errors"
	"testing"
)

func TestOnlyDefinitiveLiveSelfQueryCanConfirmUnboxed(t *testing.T) {
	if !unboxedSelfQuery(0xc000000b, nil) {
		t.Fatal("documented unboxed self-query not recognized")
	}
	for _, status := range []uintptr{0, 0xc0000022, 0xc0000001, 0xc000008b} {
		if unboxedSelfQuery(status, nil) {
			t.Fatalf("unknown or boxed status accepted: %x", status)
		}
	}
	if unboxedSelfQuery(0xc000000b, errors.New("API unavailable")) {
		t.Fatal("failed API invocation mislabeled unboxed")
	}
}
