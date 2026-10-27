package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeTemplateExclusiveOutputAndNoRuntimeClaim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.ini")
	var out, stderr bytes.Buffer
	if err := run(context.Background(), []string{"native-template", "--output", path}, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("[ExitGuard_Chrome]")) || bytes.Contains(data, []byte("NetworkEnableWFP=")) {
		t.Fatal("not a scoped template")
	}
	if bytes.Contains(out.Bytes(), []byte(`"state":"armed"`)) {
		t.Fatal("template claimed runtime protection")
	}
	if err := run(context.Background(), []string{"native-template", "--output", path}, &out, &stderr); err == nil {
		t.Fatal("overwrote existing artifact")
	}
}
