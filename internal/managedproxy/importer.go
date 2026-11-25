package managedproxy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
	"unicode/utf8"

	"exitguard/internal/subscription"
)

const importerMaxWireBytes = 32 << 20

//go:embed importer_manifest.json
var importerManifestJSON []byte
var importerManifest = func() struct {
	Protocol     int                      `json:"protocol_version"`
	CoreVersion  string                   `json:"core_version"`
	SourceCommit string                   `json:"source_commit"`
	Assets       map[string]importerAsset `json:"assets"`
} {
	var m struct {
		Protocol     int                      `json:"protocol_version"`
		CoreVersion  string                   `json:"core_version"`
		SourceCommit string                   `json:"source_commit"`
		Assets       map[string]importerAsset `json:"assets"`
	}
	if json.Unmarshal(importerManifestJSON, &m) != nil || m.Protocol != 1 || m.CoreVersion != CoreVersion || m.SourceCommit != CoreSourceCommit {
		panic("invalid native importer manifest")
	}
	return m
}()

type importerAsset struct {
	Binary string `json:"binary"`
	SHA256 string `json:"sha256"`
}
type importerExecutable struct{ Path, SHA256 string }

// NativeURIConverter delegates URI syntax and native defaults to the separately
// packaged GPL executable. It has no path/environment override and no fallback.
func NativeURIConverter(options Options) subscription.URIConverter {
	return nativeURIConverter(options, resolveImporter)
}
func resolveImporter() (importerExecutable, error) {
	exe, err := os.Executable()
	if err != nil {
		return importerExecutable{}, subscription.ErrNativeConversion
	}
	asset, ok := importerManifest.Assets[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok || len(asset.SHA256) != 64 {
		return importerExecutable{}, subscription.ErrNativeConversion
	}
	dir := filepath.Dir(exe)
	name := ""
	switch runtime.GOOS {
	case "darwin":
		dir = filepath.Join(filepath.Dir(dir), "Helpers")
		name = "mihomo-importer"
	case "windows":
		name = "MihomoImporter.exe"
	default:
		return importerExecutable{}, subscription.ErrNativeConversion
	}
	if asset.Binary != name {
		return importerExecutable{}, subscription.ErrNativeConversion
	}
	return importerExecutable{filepath.Join(dir, name), asset.SHA256}, nil
}
func nativeURIConverter(options Options, resolve func() (importerExecutable, error)) subscription.URIConverter {
	return func(ctx context.Context, lines []string) ([]subscription.URIConversion, error) {
		fail := subscription.ErrNativeConversion
		if ctx.Err() != nil || len(lines) == 0 || len(lines) > subscription.MaxNodes {
			return nil, fail
		}
		total := 0
		for _, line := range lines {
			total += len(line)
			if total > subscription.MaxBytes || !utf8.ValidString(line) {
				return nil, fail
			}
		}
		binary, err := resolve()
		if err != nil || !filepath.IsAbs(binary.Path) || verifyCore(binary.Path, binary.SHA256) != nil {
			return nil, fail
		}
		request, err := json.Marshal(struct {
			Version int      `json:"version"`
			Lines   []string `json:"lines"`
		}{1, lines})
		if err != nil || len(request) > importerMaxWireBytes {
			return nil, fail
		}
		dir, err := newRuntimeDirectory(options.RuntimeDir)
		if err != nil {
			return nil, fail
		}
		defer os.RemoveAll(dir)
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary.Path)
		cmd.Stdin = bytes.NewReader(request)
		cmd.Stderr = io.Discard
		cmd.Dir = dir
		cmd.Env = childEnvironment(dir)
		configureOwned(cmd)
		cmd.Cancel = func() error { terminateOwned(cmd); return nil }
		cmd.WaitDelay = time.Second
		output := &boundedImporterOutput{remaining: importerMaxWireBytes}
		cmd.Stdout = output
		if err = cmd.Run(); err != nil || ctx.Err() != nil || output.exceeded {
			return nil, fail
		}
		if !utf8.Valid(output.Bytes()) || uniqueImporterJSON(output.Bytes()) != nil {
			return nil, fail
		}
		var response struct {
			Version      int                          `json:"version"`
			CoreVersion  string                       `json:"core_version"`
			SourceCommit string                       `json:"source_commit"`
			Results      []subscription.URIConversion `json:"results"`
		}
		d := json.NewDecoder(bytes.NewReader(output.Bytes()))
		d.DisallowUnknownFields()
		d.UseNumber()
		if d.Decode(&response) != nil || response.Version != 1 || response.CoreVersion != CoreVersion || response.SourceCommit != CoreSourceCommit || len(response.Results) != len(lines) {
			return nil, fail
		}
		for _, result := range response.Results {
			if result.Error == "invalid_uri" && len(result.Config) == 0 {
				continue
			}
			if result.Error != "" || len(result.Config) == 0 {
				return nil, fail
			}
		}
		return response.Results, nil
	}
}

type boundedImporterOutput struct {
	buffer    bytes.Buffer
	remaining int
	exceeded  bool
}

func (b *boundedImporterOutput) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedImporterOutput) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		b.exceeded = true
		return 0, errors.New("native_importer_output_limit")
	}
	b.remaining -= len(data)
	return b.buffer.Write(data)
}

// This token walk also rejects duplicate fields inside native maps, before the
// typed envelope decoder accepts arbitrary protocol-specific configuration.
func uniqueImporterJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("native_importer_json")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("native_importer_json")
				}
				seen[s] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("native_importer_json")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("native_importer_json")
	}
	return nil
}
