package managedproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"exitguard/internal/model"
	"exitguard/internal/subscription"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeURIConverterMissingPackageFailsClosed(t *testing.T) {
	converter := NativeURIConverter(Options{RuntimeDir: filepath.Join(t.TempDir(), "runtime")})
	if _, err := converter(context.Background(), []string{"trojan://fictitious-password@node.invalid:443?metadata=native"}); err == nil {
		t.Fatal("missing packaged importer fell back to a local parser")
	}
}

func importerFixture(t *testing.T, body string) importerExecutable {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell IPC fixture; Windows cross-compiles the same launcher")
	}
	p := filepath.Join(t.TempDir(), "native-fixture")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n/bin/cat >/dev/null\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return importerExecutable{p, hex.EncodeToString(h[:])}
}
func fixtureConverter(t *testing.T, b importerExecutable) subscription.URIConverter {
	t.Helper()
	return nativeURIConverter(Options{RuntimeDir: filepath.Join(t.TempDir(), "runtime")}, func() (importerExecutable, error) { return b, nil })
}
func responseJSON(results string) string {
	return `{"version":1,"core_version":"` + CoreVersion + `","source_commit":"` + CoreSourceCommit + `","results":` + results + `}`
}
func fixturePrintJSON(data string) string {
	return "printf '%s' '" + strings.ReplaceAll(data, "'", "'\\''") + "'"
}
func TestNativeImporterStrictEnvelopeAndPrivateErrors(t *testing.T) {
	good := responseJSON(`[{"config":{"type":"trojan","server":"node.invalid","port":443,"password":"fictitious-secret"}}]`)
	for _, raw := range []string{
		strings.Replace(good, `"version":1`, `"version":2`, 1),
		strings.Replace(good, CoreVersion, "unknown-version", 1),
		strings.Replace(good, CoreSourceCommit, strings.Repeat("0", 40), 1),
		responseJSON(`[]`),
		responseJSON(`[{"error":"fictitious-secret"}]`),
		responseJSON(`[{"error":"invalid_uri","config":{"password":"fictitious-secret"}}]`),
		responseJSON(`[{}]`),
		strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(good, `"password":"fictitious-secret"`, `"password":"one","password":"fictitious-secret"`, 1),
		strings.TrimSuffix(good, "}") + `,"extra":"fictitious-secret"}`,
	} {
		b := importerFixture(t, fixturePrintJSON(raw)+"\nprintf 'fictitious-private-stderr' >&2")
		_, err := fixtureConverter(t, b)(context.Background(), []string{"trojan://fictitious-input@node.invalid:443"})
		if err != subscription.ErrNativeConversion || strings.Contains(err.Error(), "fictitious") {
			t.Fatal("invalid native envelope accepted or raw error exposed")
		}
	}
	b := importerFixture(t, fixturePrintJSON(good))
	result, err := fixtureConverter(t, b)(context.Background(), []string{"trojan://fictitious-input@node.invalid:443"})
	if err != nil || len(result) != 1 || result[0].Config["password"] != "fictitious-secret" {
		t.Fatal("private native config not preserved")
	}
}
func TestNativeImporterTamperCancellationAndOutputBound(t *testing.T) {
	b := importerFixture(t, fixturePrintJSON(responseJSON(`[{"error":"invalid_uri"}]`)))
	b.SHA256 = strings.Repeat("0", 64)
	if _, err := fixtureConverter(t, b)(context.Background(), []string{"invalid://fixture"}); err != subscription.ErrNativeConversion {
		t.Fatal("tampered helper accepted")
	}
	b = importerFixture(t, "/bin/sleep 20")
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := fixtureConverter(t, b)(ctx, []string{"invalid://fixture"}); err != subscription.ErrNativeConversion || time.Since(start) > 2*time.Second {
		t.Fatal("cancellation did not bound child lifetime")
	}
	b = importerFixture(t, "/usr/bin/head -c 33554433 /dev/zero")
	if _, err := fixtureConverter(t, b)(context.Background(), []string{"invalid://fixture"}); err != subscription.ErrNativeConversion {
		t.Fatal("unbounded native stdout accepted")
	}
}
func TestRealNativeImporterPreservesNativeMapsAndKeepsFailureQuiet(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("current native fixture target")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, ".work/native-importer/darwin-arm64/mihomo-importer")
	if _, err = os.Stat(p); err != nil {
		t.Skip("build the pinned native importer fixture first")
	}
	asset := importerManifest.Assets["darwin/arm64"]
	b := importerExecutable{p, asset.SHA256}
	lines := []string{"trojan://fictitious-password@node.invalid:443?allowInsecure=0&peer=tls.invalid&sni=tls.invalid&type=tcp&unknown-native-metadata=retained", "vless://fictitious-private-marker"}
	result, err := fixtureConverter(t, b)(context.Background(), lines)
	if err != nil || len(result) != 2 || result[0].Config["type"] != "trojan" || result[0].Config["client-fingerprint"] != "chrome" || result[1].Error != "invalid_uri" {
		t.Fatal("real native converter did not preserve upstream output")
	}
	request, _ := json.Marshal(map[string]any{"version": 1, "lines": []string{lines[1]}})
	cmd := exec.Command(p)
	cmd.Stdin = bytes.NewReader(request)
	cmd.Env = childEnvironment(t.TempDir())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil || strings.Contains(stdout.String(), "fictitious-private-marker") || stderr.Len() != 0 {
		t.Fatal("native malformed line leaked through stdout/stderr")
	}
}

func TestNativeOutputBoundCannotBeBypassedByReaderFrom(t *testing.T) {
	output := &boundedImporterOutput{remaining: 4}
	_, err := io.Copy(output, struct{ io.Reader }{strings.NewReader("fictitious-oversized-output")})
	if err == nil || len(output.Bytes()) > 4 || !output.exceeded {
		t.Fatal("stream copy bypassed the native output bound")
	}
}

func TestRealNativeImporterThroughParserAndPrivateStore(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("current native fixture target")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, ".work/native-importer/darwin-arm64/mihomo-importer")
	if _, err = os.Stat(p); err != nil {
		t.Skip("build the pinned native importer fixture first")
	}
	convert := fixtureConverter(t, importerExecutable{p, importerManifest.Assets["darwin/arm64"].SHA256})
	raw := []byte("trojan://fictitious-password@node.invalid:443?type=ws&path=/fixture&sni=tls.invalid&allowInsecure=1&provider-metadata=compatible#Fixture")
	first, err := subscription.ParseWithURIConverter(context.Background(), raw, convert)
	if err != nil || len(first) != 1 || !first[0].Supported || first[0].Config["skip-cert-verify"] != true {
		t.Fatal("real native defaults failed the importer capability boundary")
	}
	next, err := subscription.ParseWithURIConverter(context.Background(), raw, convert)
	if err != nil || len(next) != 1 || next[0].ID != first[0].ID {
		t.Fatal("actual native WS defaults changed identity")
	}
	lib := subscription.Empty()
	record, err := lib.PrepareWithURIConverter(context.Background(), model.SubscriptionInput{Name: "Fixture", Content: raw}, nil, convert)
	if err != nil || lib.Put(record) != nil {
		t.Fatal("real native candidate could not enter private library")
	}
	data, err := subscription.Encode(lib)
	if err != nil {
		t.Fatal("real native candidate could not encode")
	}
	restored, err := subscription.Decode(data)
	if err != nil || len(restored.Records) != 1 || restored.Records[0].Nodes[0].ID != first[0].ID || restored.Records[0].Nodes[0].Config["skip-cert-verify"] != true {
		t.Fatal("real native map failed exact private persistence")
	}
	public, _ := json.Marshal(restored.Summaries())
	if strings.Contains(string(public), "fictitious-password") || strings.Contains(string(public), "node.invalid") {
		t.Fatal("private native map leaked into summaries")
	}
}
func TestNativeRuntimeRetainsExactIntegerAndNativeCoreType(t *testing.T) {
	n := testNode()
	n.Config["future-native-counter"] = json.Number("9007199254740993")
	n.Identity = subscription.Identity(n.Config)
	data, err := generateConfig(n, "8.8.8.8", 34567, 34568, "fixture-user", "fixture-password", strings.Repeat("s", 32))
	if err != nil || !bytes.Contains(data, []byte(`9007199254740993`)) || validateRuntimeConfig(data) != nil {
		t.Fatal("native integer rounded or rejected during dedicated runtime config validation")
	}
	if coreType("ssr") != "ShadowsocksR" {
		t.Fatal("native SSR controller type would fail owned readiness attestation")
	}
}
