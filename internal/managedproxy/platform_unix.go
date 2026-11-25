//go:build !windows

package managedproxy

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func childEnvironment(dir string) []string {
	return []string{"TMPDIR=" + dir, "LANG=C", "LC_ALL=C"}
}
func configureOwned(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func terminateOwned(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
func terminateCore(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
}
func coreProcessOptions(cmd *exec.Cmd) (func(), error) { return func() {}, nil }
func newRuntimeDirectory(parent string) (string, error) {
	if parent == "" || !filepath.IsAbs(parent) {
		return "", ErrStorage
	}
	// Resolve ancestors without accepting user-created directory symlinks.
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(parent), current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			err = os.Mkdir(current, 0700)
			if err == nil {
				info, err = os.Lstat(current)
			}
		}
		if err != nil {
			return "", ErrStorage
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, e := filepath.EvalSymlinks(current)
			if e != nil || !((current == "/var" && resolved == "/private/var") || (current == "/tmp" && resolved == "/private/tmp")) {
				return "", ErrStorage
			}
		} else if !info.IsDir() {
			return "", ErrStorage
		}
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0700 {
		return "", ErrStorage
	}
	dir, err := os.MkdirTemp(parent, "session-")
	if err != nil {
		return "", ErrStorage
	}
	return dir, nil
}
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrStorage
	}
	defer f.Close()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return ErrStorage
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrStorage
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, ErrStorage
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrStorage
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrStorage
	}
	data, err := io.ReadAll(io.LimitReader(f, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return nil, ErrStorage
	}
	return data, nil
}
