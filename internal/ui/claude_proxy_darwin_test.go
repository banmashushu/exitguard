package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMacClaudeManagedProxyLaunch(t *testing.T) {
	const pin = `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`
	const other = `<key>egressProxyUrl</key><string>http://127.0.0.1:17891</string>`
	const pac = `<key>egressProxyPacUrl</key><string>https://proxy.example.test/config.pac</string>`
	for _, tc := range []struct {
		name, device, user string
		plain, wantErr     bool
	}{
		{name: "no managed policy"},
		{name: "unrelated policy", device: `<key>unrelated</key><true/>`},
		{name: "device pin", device: pin, plain: true},
		{name: "user pin", user: pin, plain: true},
		{name: "user overrides device URL", device: other, user: pin, plain: true},
		{name: "user inherits device URL", device: pin, user: `<key>unrelated</key><true/>`, plain: true},
		{name: "user mismatch overrides device pin", device: pin, user: other, wantErr: true},
		{name: "device mismatch", device: other, wantErr: true},
		{name: "PAC takes precedence", device: pin + pac, wantErr: true},
		{name: "device PAC survives user fixed URL", device: pac, user: pin, wantErr: true},
		{name: "user PAC overrides device fixed URL", device: pin, user: pac, wantErr: true},
		{name: "PAC without fixed URL", device: pac, wantErr: true},
		{name: "empty URL", device: `<key>egressProxyUrl</key><string></string>`, wantErr: true},
		{name: "wrong URL type", device: `<key>egressProxyUrl</key><integer>17890</integer>`, wantErr: true},
		{name: "wrong PAC type", device: pin + `<key>egressProxyPacUrl</key><false/>`, wantErr: true},
		{name: "nonexact URL", device: `<key>egressProxyUrl</key><string>http://127.0.0.1:17890/</string>`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := macClaudeCommandFixture(t)
			originalArgs := strings.Join(command.Args, "\x00")
			paths := macClaudePolicyFixture(t, tc.device, tc.user)
			err := prepareClaudeManagedCommand(command, "127.0.0.1:17890", paths)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if tc.plain {
				if len(command.Args) != 1 || command.Args[0] != command.Path {
					t.Fatalf("verified managed proxy still received rejected networking switches: %q", command.Args)
				}
			} else if strings.Join(command.Args, "\x00") != originalArgs {
				t.Fatal("unverified managed policy removed proxy arguments")
			}
		})
	}
}

func TestMacClaudeManagedProxyReadErrorsRefuseLaunch(t *testing.T) {
	for _, failure := range []string{"malformed", "directory", "oversized", "symlink"} {
		t.Run(failure, func(t *testing.T) {
			command := macClaudeCommandFixture(t)
			paths := macClaudePolicyFixture(t, `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`, "")
			switch failure {
			case "malformed":
				if err := os.WriteFile(paths[1], []byte("invalid plist"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(paths[1], 0700); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(paths[1], make([]byte, 128<<10+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(paths[0], paths[1]); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareClaudeManagedCommand(command, "127.0.0.1:17890", paths); err == nil {
				t.Fatal("unreadable managed policy allowed launch")
			}
			if len(command.Args) == 1 {
				t.Fatal("policy read error removed proxy arguments")
			}
		})
	}
}

func TestMacClaudeManagedProxyAcceptsBinaryPlist(t *testing.T) {
	command := macClaudeCommandFixture(t)
	paths := macClaudePolicyFixture(t, `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`, "")
	if err := exec.Command("/usr/bin/plutil", "-convert", "binary1", "--", paths[0]).Run(); err != nil {
		t.Fatal(err)
	}
	if err := prepareClaudeManagedCommand(command, "127.0.0.1:17890", paths); err != nil || len(command.Args) != 1 {
		t.Fatalf("binary managed proxy rejected: args=%q error=%v", command.Args, err)
	}
}

func TestMacClaudeManagedProxyRequiresSupportedVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		allowed bool
	}{
		{"1.44121.1", true},
		{"1.44121.2", true},
		{"1.44122.0", true},
		{"2.0.0", true},
		{"4.29.0", true},
		{"1.44121.0", false},
		{"1.44120.999", false},
		{"0.99999.999", false},
		{"", false},
		{"unknown", false},
		{"4.29", false},
		{"4.29.0.1", false},
		{"4.29.0-beta", false},
		{"+4.29.0", false},
		{" 4.29.0", false},
		{"4..0", false},
		{"4.29.999999999999999999999999999999999999999", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			for _, binary := range []bool{false, true} {
				command := macClaudeCommandFixture(t)
				paths := macClaudePolicyFixture(t, `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`, "")
				metadataPath := filepath.Join(filepath.Dir(filepath.Dir(command.Path)), "Info.plist")
				version := ""
				if tc.version != "" {
					version = `<key>CFBundleShortVersionString</key><string>` + tc.version + `</string>`
				}
				metadata := `<plist><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Claude</string>` + version + `</dict></plist>`
				if err := os.WriteFile(metadataPath, []byte(metadata), 0600); err != nil {
					t.Fatal(err)
				}
				if binary {
					if err := exec.Command("/usr/bin/plutil", "-convert", "binary1", "--", metadataPath).Run(); err != nil {
						t.Fatal(err)
					}
				}
				err := prepareClaudeManagedCommand(command, "127.0.0.1:17890", paths)
				if (err == nil) != tc.allowed {
					t.Fatalf("binary=%v, error=%v, want supported=%v", binary, err, tc.allowed)
				}
				if (len(command.Args) == 1) != tc.allowed {
					t.Fatalf("binary=%v, unsupported version changed launch arguments: %q", binary, command.Args)
				}
			}
		})
	}
}

func TestMacClaudeManagedProxyRequiresClaudeBundle(t *testing.T) {
	for _, invalid := range []string{"standalone", "wrong bundle ID"} {
		t.Run(invalid, func(t *testing.T) {
			command := macClaudeCommandFixture(t)
			paths := macClaudePolicyFixture(t, `<key>egressProxyUrl</key><string>http://127.0.0.1:17890</string>`, "")
			if invalid == "standalone" {
				command.Path = filepath.Join(t.TempDir(), "Claude")
				if err := os.WriteFile(command.Path, []byte("fixture"), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(filepath.Dir(filepath.Dir(command.Path)), "Info.plist")
				if err := os.WriteFile(path, []byte(`<plist><dict><key>CFBundleIdentifier</key><string>other.app</string><key>CFBundleExecutable</key><string>Claude</string></dict></plist>`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareClaudeManagedCommand(command, "127.0.0.1:17890", paths); err == nil {
				t.Fatal("managed proxy used for an unverified Claude app")
			}
		})
	}
}

func macClaudeCommandFixture(t *testing.T) *exec.Cmd {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	contents := filepath.Join(root, "Claude.app", "Contents")
	path := filepath.Join(contents, "MacOS", "Claude")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture executable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(`<plist><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Claude</string><key>CFBundleShortVersionString</key><string>4.29.0</string></dict></plist>`), 0600); err != nil {
		t.Fatal(err)
	}
	c, s := proxyOnlyFixture(t)
	command, err := claudeCommand(c, s, launchRequest{Kind: "claude", Path: path}, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func macClaudePolicyFixture(t *testing.T, values ...string) []string {
	t.Helper()
	root := t.TempDir()
	paths := make([]string, len(values))
	for i, value := range values {
		paths[i] = filepath.Join(root, fmt.Sprintf("policy-%d.plist", i))
		if value != "" {
			data := `<?xml version="1.0"?><plist version="1.0"><dict>` + value + `</dict></plist>`
			if err := os.WriteFile(paths[i], []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return paths
}
