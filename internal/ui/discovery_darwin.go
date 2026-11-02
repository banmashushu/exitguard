package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const discoveryTimeout = 3 * time.Second
const maxBundleMetadata = 128 << 10

func installedDesktopApplications(ctx context.Context) []desktopApplication {
	dirs := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return discoverMacApplications(ctx, dirs)
}

func discoverMacApplications(ctx context.Context, dirs []string) []desktopApplication {
	specs := []struct{ bundle, id, executable, kind, name string }{
		{"Google Chrome.app", "com.google.Chrome", "Google Chrome", "browser", "Chrome"},
		{"Microsoft Edge.app", "com.microsoft.edgemac", "Microsoft Edge", "browser", "Edge"},
		{"Claude.app", "com.anthropic.claudefordesktop", "Claude", "claude", "Claude Desktop / Code"},
	}
	apps := make([]desktopApplication, 0, 6)
	seen := make(map[string]bool)
	for _, dir := range dirs {
		if !discoveryDirectory(dir) {
			continue
		}
		for _, spec := range specs {
			if ctx.Err() != nil {
				return apps
			}
			bundle := filepath.Join(dir, spec.bundle)
			if !discoveryDirectory(bundle) || !discoveryDirectory(filepath.Join(bundle, "Contents")) || !discoveryDirectory(filepath.Join(bundle, "Contents", "MacOS")) {
				continue
			}
			metadata, err := bundleMetadata(ctx, filepath.Join(bundle, "Contents", "Info.plist"))
			if err != nil || metadata["CFBundleIdentifier"] != spec.id || metadata["CFBundleExecutable"] != spec.executable {
				continue
			}
			entry := filepath.Join(bundle, "Contents", "MacOS", spec.executable)
			info, err := os.Lstat(entry)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				continue
			}
			path, err := canonicalExecutable(entry, "darwin")
			if err != nil || seen[path] {
				continue
			}
			resolvedBundle, err := filepath.EvalSymlinks(bundle)
			if err != nil || !strings.HasPrefix(path, resolvedBundle+string(filepath.Separator)) {
				continue
			}
			seen[path] = true
			apps = append(apps, desktopApplication{Kind: spec.kind, Name: spec.name, Path: path, BundleID: spec.id})
		}
	}
	return apps
}

func discoveryDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func bundleMetadata(ctx context.Context, path string) (map[string]string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBundleMetadata {
		return nil, errors.New("invalid bundle metadata")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBundleMetadata+1))
	_ = f.Close()
	if err != nil || len(data) > maxBundleMetadata {
		return nil, errors.New("invalid bundle metadata")
	}
	if bytes.HasPrefix(data, []byte("bplist")) {
		// Convert only the already bounded bytes: never reopen a mutable path or
		// execute a client, even if the bundle changes during discovery.
		cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", "-")
		cmd.Stdin = bytes.NewReader(data)
		var out boundedMetadata
		cmd.Stdout, cmd.Stderr = &out, io.Discard
		if err := cmd.Run(); err != nil {
			return nil, err
		}
		var values map[string]any
		if err := json.Unmarshal(out.Bytes(), &values); err != nil {
			return nil, err
		}
		result := make(map[string]string)
		for _, key := range []string{"CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString"} {
			result[key], _ = values[key].(string)
		}
		return result, nil
	}
	var plist struct {
		Dict struct {
			Elements []struct {
				XMLName xml.Name
				Text    string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(data, &plist); err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for i := 0; i+1 < len(plist.Dict.Elements); i++ {
		key, value := plist.Dict.Elements[i], plist.Dict.Elements[i+1]
		if key.XMLName.Local == "key" && value.XMLName.Local == "string" {
			result[key.Text] = value.Text
			i++
		}
	}
	return result, nil
}

type boundedMetadata struct{ bytes.Buffer }

func (b *boundedMetadata) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxBundleMetadata {
		return 0, errors.New("bundle metadata too large")
	}
	return b.Buffer.Write(data)
}
