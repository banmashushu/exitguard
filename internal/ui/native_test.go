package ui

import (
	"context"
	"testing"
)

type nativeTestService struct {
	testService
	calls    int
	revision uint64
	ack      bool
}

func (s *nativeTestService) LaunchNativePreview(_ context.Context, target, path string, revision uint64, ack bool) error {
	s.calls++
	s.revision = revision
	s.ack = ack
	return nil
}
func TestNativePreviewNeedsAuthenticatedLiveAPIAndExplicitRevision(t *testing.T) {
	s := &nativeTestService{}
	h := &handler{service: s, host: "127.0.0.1:12345", token: "test-token"}
	body := `{"target":"chrome","path":"C:\\Apps\\chrome.exe","sessionRevision":7,"acknowledgePreview":true}`
	if w := request(h, "POST", "/api/native-launch-preview", body, "", "127.0.0.1:12345", ""); w.Code != 401 || s.calls != 0 {
		t.Fatal("unauthenticated launch")
	}
	if w := request(h, "POST", "/api/native-launch-preview", `{"target":"chrome","path":"C:\\Apps\\chrome.exe","acknowledgePreview":true}`, "test-token", "127.0.0.1:12345", ""); w.Code != 400 || s.calls != 0 {
		t.Fatal("absent current revision")
	}
	if w := request(h, "POST", "/api/native-launch-preview", body, "test-token", "127.0.0.1:12345", ""); w.Code != 200 || s.calls != 1 || s.revision != 7 || !s.ack {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
