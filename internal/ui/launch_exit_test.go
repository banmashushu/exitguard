package ui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLaunchExitHelper(t *testing.T) {
	switch os.Getenv("EXITGUARD_LAUNCH_TEST") {
	case "refused":
		fmt.Fprintln(os.Stderr, "Claude: refusing to start — a debugging or network-override switch is present on the command line.")
		os.Exit(1)
	case "failed":
		fmt.Fprintln(os.Stderr, "private-client-diagnostic")
		os.Exit(2)
	case "handoff":
		os.Exit(0)
	case "running":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestLaunchReportsEarlyExit(t *testing.T) {
	for _, tc := range []struct {
		mode, want string
	}{
		{"refused", "不接受代理启动参数"},
		{"failed", "启动后立即退出"},
		{"handoff", ""},
		{"running", ""},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			config, status := proxyOnlyFixture(t)
			service := &testService{config: config, status: status}
			command := exec.Command(os.Args[0], "-test.run=^TestLaunchExitHelper$")
			command.Env = append(os.Environ(), "EXITGUARD_LAUNCH_TEST="+tc.mode, "GORACE=atexit_sleep_ms=0")
			t.Cleanup(func() {
				if command.Process != nil {
					_ = command.Process.Kill()
				}
			})
			started := time.Now()
			err := startIfArmed(service, status, command)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted %q, got %v", tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-client-diagnostic") {
				t.Fatal("raw client diagnostics were exposed")
			}
			if time.Since(started) > 5*time.Second {
				t.Fatal("launch blocked waiting for the client lifetime")
			}
		})
	}
}
