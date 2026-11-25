package managedproxy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const CoreVersion = "v1.19.33"
const CoreSourceCommit = "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8"

type bundle struct{ supervisor, core, hash string }

//go:embed manifest.json
var manifestJSON []byte
var pinnedManifest = func() struct {
	Version string `json:"version"`
	Assets  map[string]struct {
		Hash string `json:"binary_sha256"`
	} `json:"assets"`
} {
	var m struct {
		Version string `json:"version"`
		Assets  map[string]struct {
			Hash string `json:"binary_sha256"`
		} `json:"assets"`
	}
	if json.Unmarshal(manifestJSON, &m) != nil || m.Version != CoreVersion {
		panic("invalid managed proxy manifest")
	}
	return m
}()

func coreHash() string { return pinnedManifest.Assets[runtime.GOOS+"/"+runtime.GOARCH].Hash }
func coreIdentity() string {
	return "mihomo/" + CoreVersion + "/" + runtime.GOOS + "/" + runtime.GOARCH + "/sha256:" + coreHash()
}
func resolveBundle() (bundle, error) {
	exe, err := os.Executable()
	if err != nil {
		return bundle{}, ErrPackage
	}
	dir := filepath.Dir(exe)
	if runtime.GOOS == "darwin" {
		dir = filepath.Join(filepath.Dir(dir), "Helpers")
		return bundle{filepath.Join(dir, "exitguard-proxy-supervisor"), filepath.Join(dir, "mihomo"), coreHash()}, nil
	}
	if runtime.GOOS == "windows" {
		return bundle{filepath.Join(dir, "ExitGuardProxySupervisor.exe"), filepath.Join(dir, "mihomo.exe"), coreHash()}, nil
	}
	return bundle{}, ErrPackage
}
func verifyBundle(b bundle) error {
	if b.hash == "" || !filepath.IsAbs(b.core) || !filepath.IsAbs(b.supervisor) {
		return ErrPackage
	}
	for _, p := range []string{b.core, b.supervisor} {
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() {
			return ErrPackage
		}
	}
	return verifyCore(b.core, b.hash)
}
func verifyCore(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ErrPackage
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrPackage
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return ErrPackage
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, 128<<20)); err != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrPackage
	}
	return nil
}
