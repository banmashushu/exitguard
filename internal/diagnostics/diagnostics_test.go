package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReportFiltersAppsAndRedactsUserPaths(t *testing.T) {
	raw := []rawApp{
		{Name: "Clash Party.exe", Path: `C:\Users\alice\AppData\Local\Programs\Clash Party\Clash Party.exe`, Running: true},
		{Name: "Claude.exe", Path: `D:\Profiles\alice\Claude.exe`, Running: true},
		{Name: "password-manager.exe", Path: `C:\Users\alice\secret.txt`, Running: true},
		{Name: "chrome.exe --token=secret", Path: `C:\Users\alice\secret`, Running: true},
	}
	apps := applicationFacts(raw, []string{`D:\Profiles\alice`}, true)
	data, err := json.Marshal(apps)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"alice", "password-manager", "secret", "--token"} {
		if strings.Contains(text, secret) {
			t.Fatalf("report leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "%USERPROFILE%") || len(apps) != 4 {
		t.Fatalf("bad allowlist/redaction: %s", text)
	}
	if apps[0].Detected != "detected" || apps[1].Running != "running" {
		t.Fatalf("allowed app facts missing: %+v", apps)
	}
}

func TestRedactionHonorsPathBoundaries(t *testing.T) {
	for _, test := range []struct{ path, home, want string }{
		{`C:\Users\alice\Claude.exe`, `C:\Users\alice`, `%USERPROFILE%\Claude.exe`},
		{`c:\users\BOB\App\chrome.exe`, `D:\home`, `%USERPROFILE%\App\chrome.exe`},
		{`D:\Profiles\alice-other\chrome.exe`, `D:\Profiles\alice`, `D:\Profiles\alice-other\chrome.exe`},
		{`/Users/alice/Claude.app`, `/Users/alice`, `%USERPROFILE%/Claude.app`},
	} {
		if got := redactPath(test.path, []string{test.home}); got != test.want {
			t.Fatalf("redaction = %q, want %q", got, test.want)
		}
	}
}

func TestProbesAreFixedLoopbackBoundedAndSendNoBytes(t *testing.T) {
	var addresses []string
	var peers []net.Conn
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp4" {
			t.Fatalf("network = %s", network)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 300*time.Millisecond {
			t.Fatal("probe missing short deadline")
		}
		addresses = append(addresses, address)
		a, b := net.Pipe()
		peers = append(peers, b)
		return a, nil
	}
	results := probePorts(context.Background(), dial)
	want := []string{"127.0.0.1:7890", "127.0.0.1:7891", "127.0.0.1:7892", "127.0.0.1:7897", "127.0.0.1:9090", "127.0.0.1:17890", "127.0.0.1:17891"}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("unsafe probe targets: %v", addresses)
	}
	for i, peer := range peers {
		var buf [1]byte
		n, err := peer.Read(buf[:])
		peer.Close()
		if n != 0 || err != io.EOF {
			t.Fatalf("probe sent payload: %d %v", n, err)
		}
		if results[i].TCPReachable == nil || !*results[i].TCPReachable {
			t.Fatalf("result: %+v", results[i])
		}
	}
}

func TestProbePermissionOrCanceledIsUnknown(t *testing.T) {
	for _, denied := range []error{os.ErrPermission, syscall.Errno(10013), context.Canceled, context.DeadlineExceeded} {
		results := probePorts(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, denied })
		for _, result := range results {
			if result.TCPReachable != nil {
				t.Fatalf("%v reported %v", denied, result.TCPReachable)
			}
		}
	}
	results := probePorts(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unavailable") })
	if results[0].TCPReachable != nil {
		t.Fatal("unknown error must remain unknown", results)
	}
	results = probePorts(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.ECONNREFUSED}
	})
	if results[0].TCPReachable == nil || *results[0].TCPReachable {
		t.Fatal("refused connection should be false", results)
	}
}

func TestMissingMetadataRemainsUnknownAndReportIsDiagnostic(t *testing.T) {
	report := collect(context.Background(), func(context.Context) platformData { return platformData{Windows: unknownWindows("unknown")} }, func(context.Context, string, string) (net.Conn, error) { return nil, os.ErrPermission })
	if report.SchemaVersion != 1 || report.ProtectionAssessed || report.Windows.BFE != "unknown" || report.Windows.Elevated != "unknown" {
		t.Fatalf("missing data overstated: %+v", report)
	}
	if report.GeneratedAt.IsZero() || len(report.Applications) != 4 {
		t.Fatal("incomplete report")
	}
	for _, app := range report.Applications {
		if app.Running != "unknown" {
			t.Fatal("incomplete discovery claimed absent")
		}
	}
}

func TestMetadataParserDropsUnknownFieldsAndUntrustedValues(t *testing.T) {
	data, err := parseWindowsMetadata([]byte(`{"version":"10.0.22631","build":"22631","bfe":"Running","elevated":"no","apps":[{"name":"Claude.exe","path":"C:\\Users\\alice\\Claude.exe"},{"name":"other.exe","path":"secret"}],"computer":"secret","token":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if data.Windows.Version != "10.0.22631" || data.Windows.BFE != "running" || len(applicationFacts(data.Apps, nil, true)) != 4 {
		t.Fatalf("bad metadata: %+v", data)
	}
	bad, err := parseWindowsMetadata([]byte(`{"version":"alice-secret","build":"token","bfe":"secret","elevated":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bad.Windows.Version != "" || bad.Windows.BFE != "unknown" || bad.Windows.Elevated != "unknown" {
		t.Fatal("untrusted metadata retained")
	}
	if _, err := parseWindowsMetadata([]byte("not json")); err == nil {
		t.Fatal("invalid metadata accepted")
	}
}

func TestReportUsesOnlyRunningProcessEvidence(t *testing.T) {
	report := collect(context.Background(), func(context.Context) platformData {
		return platformData{
			Windows: unknownWindows("unknown"), DiscoveryComplete: true,
			Apps: []rawApp{
				{Name: "Clash Party.exe", Path: `C:\Users\alice\Clash Party.exe`, Running: true},
				// File-location candidates, including remote paths, are not process evidence.
				{Name: "Claude.exe", Path: `\\remote\share\Claude.exe`, Running: false},
				{Name: "chrome.exe", Path: `C:\Programs\Google\Chrome\Application\chrome.exe`, Running: false},
			},
		}
	}, func(context.Context, string, string) (net.Conn, error) { return nil, context.Canceled })
	for _, app := range report.Applications[1:] {
		if app.Detected != "not_detected" || app.Running != "not_detected" || len(app.Paths) != 0 {
			t.Fatalf("non-running file candidate treated as discovery: %+v", app)
		}
	}
	if report.Applications[0].Running != "running" || report.ApplicationDiscovery != "limited_running_processes" {
		t.Fatalf("running-only discovery mislabeled: %+v", report)
	}
}
