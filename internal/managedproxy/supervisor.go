package managedproxy

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// RunSupervisor accepts only an ExitGuard-created private runtime directory.
// Its stdin is a lifetime pipe owned by the parent; the child receives /dev/null.
// It has no socket API and can only launch the adjacent pinned packaged core.
func RunSupervisor(args []string, life io.Reader) int {
	if len(args) != 2 || args[0] != "--runtime" || !filepath.IsAbs(args[1]) {
		return 2
	}
	dir := args[1]
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 3
	}
	data, err := readPrivate(filepath.Join(dir, "config.json"))
	if err != nil || validateRuntimeConfig(data) != nil {
		return 3
	}
	exe, err := os.Executable()
	if err != nil {
		return 4
	}
	core := filepath.Join(filepath.Dir(exe), "mihomo")
	if runtime.GOOS == "windows" {
		core += ".exe"
	}
	if verifyCore(core, coreHash()) != nil {
		return 4
	}
	eof := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, life); close(eof) }()
	select {
	case <-eof:
		return 0
	default:
	}
	cmd := exec.Command(core, "-d", dir, "-f", filepath.Join(dir, "config.json"))
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = childEnvironment(dir)
	cmd.Dir = dir
	release, err := coreProcessOptions(cmd)
	if err != nil {
		return 5
	}
	defer func() { _ = os.RemoveAll(dir); release() }()
	if cmd.Start() != nil {
		return 5
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	select {
	case <-exited:
		return 6
	case <-eof:
	}
	terminateCore(cmd)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(time.Second):
			return 7
		}
	}
	_ = os.RemoveAll(dir)
	return 0
}
