package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"exitguard/internal/model"
)

type consoleFixture struct {
	launched []string
	paused   bool
	revision uint64
}

func (s *consoleFixture) Config() model.Config {
	return model.Config{Programs: []string{`C:\Chrome\chrome.exe`, `C:\Edge\msedge.exe`, `C:\Claude\Claude.exe`}}
}
func (s *consoleFixture) Status() model.Status {
	return model.Status{State: "proxy_active", SessionRevision: s.revision}
}
func (s *consoleFixture) Disarm()                   { s.paused = true; s.revision++ }
func (s *consoleFixture) Arm(context.Context) error { s.paused = false; s.revision++; return nil }
func (s *consoleFixture) LaunchNativePreview(_ context.Context, target, path string, revision uint64, ack bool) error {
	if revision != s.revision || !ack {
		panic("stale or unacknowledged console launch")
	}
	s.launched = append(s.launched, target+":"+path)
	return nil
}
func TestNativeConsoleCanLaunchAllThreeAndKeepControlWithoutBrowser(t *testing.T) {
	fixture := &consoleFixture{revision: 7}
	var output bytes.Buffer
	err := nativeConsole(context.Background(), fixture, strings.NewReader("1\n\n2\n\n5\n6\n3\n\n4\n0\n"), &output, func() error { t.Fatal("unexpected browser-control dependency"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(fixture.launched, "|") != `chrome:C:\Chrome\chrome.exe|edge:C:\Edge\msedge.exe|claude:C:\Claude\Claude.exe` || fixture.paused || fixture.revision != 9 {
		t.Fatal(fixture)
	}
	if !strings.Contains(output.String(), "尚未完成 Windows 实机测试") {
		t.Fatal("missing trial limitation")
	}
}
