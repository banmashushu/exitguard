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

func TestDoctorDoesNotLoadGuardConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	guardDir := filepath.Join(configDir, "ExitGuard")
	if err := os.MkdirAll(guardDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(guardDir, "config.json")
	original := []byte("MALFORMED-CONFIG-SECRET")
	if err := os.WriteFile(configPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if err := run(ctx, []string{"doctor"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var report struct {
		SchemaVersion      int   `json:"schema_version"`
		ProtectionAssessed *bool `json:"protection_assessed"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || (report.ProtectionAssessed == nil || *report.ProtectionAssessed) || stderr.Len() != 0 {
		t.Fatalf("bad report: %s %s", stdout.String(), stderr.String())
	}
	current, _ := os.ReadFile(configPath)
	if !bytes.Equal(current, original) || strings.Contains(stdout.String(), "SECRET") {
		t.Fatal("doctor touched/leaked guard config")
	}
	entries, _ := os.ReadDir(guardDir)
	if len(entries) != 1 {
		t.Fatal("doctor created guard state")
	}
}

func TestDoctorWritesOnlyExplicitReportAndRejectsGuardFlags(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "report.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if err := run(ctx, []string{"doctor", "--output", output}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || !json.Valid(data) || stdout.Len() != 0 {
		t.Fatalf("bad output: %v %s %s", err, data, stdout.String())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("extra output files")
	}
	for _, args := range [][]string{{"doctor", "--config", "secret"}, {"doctor", "filter-install"}, {"doctor", "--output", ""}} {
		stdout.Reset()
		stderr.Reset()
		if err := run(ctx, args, &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatalf("doctor accepted unsupported args: %v", args)
		}
	}
}
