package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exitguard/internal/model"
	"exitguard/internal/ui"
)

func TestServeReadyChannelHasFragmentTokenAndCleanLogs(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	config := model.Config{Mode: "feilian", ProxyPort: port, ProbeURL: "https://api.ipify.org?format=json"}
	data, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var stdout, stderr bytes.Buffer
	if err := run(ctx, []string{"serve", "--no-open", "--config", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var ready ui.Ready
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ready.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Ready || u.Hostname() != "127.0.0.1" || u.RawQuery != "" || !strings.HasPrefix(u.Fragment, "token=") {
		t.Fatalf("bad ready channel: %#v", ready)
	}
	if stderr.Len() != 0 || stdout.Len() != 0 {
		t.Fatalf("extra logs on ready channel: %q %q", stdout.String(), stderr.String())
	}
}

func TestUnknownCommandCannotReachPrivilegedOperation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"install"}, &stdout, &stderr); err == nil {
		t.Fatal("ambiguous install command accepted")
	}
	if stdout.Len() != 0 {
		t.Fatal("unknown command emitted ready credential")
	}
}
