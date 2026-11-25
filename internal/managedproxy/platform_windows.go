package managedproxy

import (
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var managedKernel32 = syscall.NewLazyDLL("kernel32.dll")
var managedCreateJob = managedKernel32.NewProc("CreateJobObjectW")
var managedSetJob = managedKernel32.NewProc("SetInformationJobObject")
var managedAssignJob = managedKernel32.NewProc("AssignProcessToJobObject")
var managedWindowsDirectory = managedKernel32.NewProc("GetWindowsDirectoryW")

func childEnvironment(dir string) []string {
	var buf [32768]uint16
	n, _, _ := managedWindowsDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return []string{"TEMP=" + dir, "TMP=" + dir}
	}
	return []string{"SystemRoot=" + syscall.UTF16ToString(buf[:n]), "TEMP=" + dir, "TMP=" + dir}
}
func configureOwned(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
func terminateOwned(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
func terminateCore(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
func coreProcessOptions(cmd *exec.Cmd) (func(), error) {
	configureOwned(cmd)
	h, _, _ := managedCreateJob.Call(0, 0)
	if h == 0 {
		return nil, ErrStart
	}
	// The helper joins before starting the core. Children inherit the job, so
	// even abrupt helper death closes its sole job handle and kills its core.
	var info struct {
		PerProcess, PerJob                             int64
		Flags                                          uint32
		Min, Max                                       uintptr
		Active                                         uint32
		Affinity                                       uintptr
		Priority, Scheduling                           uint32
		IO                                             [6]uint64
		ProcessMemory, JobMemory, PeakProcess, PeakJob uintptr
	}
	info.Flags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ok, _, _ := managedSetJob.Call(h, 9, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if ok == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return nil, ErrStart
	}
	self, _ := syscall.GetCurrentProcess()
	ok, _, _ = managedAssignJob.Call(h, uintptr(self))
	if ok == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return nil, ErrStart
	}
	return func() { _ = syscall.CloseHandle(syscall.Handle(h)) }, nil
}
func newRuntimeDirectory(parent string) (string, error) {
	if parent == "" || !filepath.IsAbs(parent) {
		return "", ErrStorage
	}
	nonce := randomToken()
	if nonce == "" {
		return "", ErrStorage
	}
	dir := filepath.Join(parent, "session-"+nonce)
	_, parents, err := lockCredentialParents(filepath.Join(dir, "config.json"), true)
	if err != nil {
		return "", ErrStorage
	}
	parents.close()
	return dir, nil
}
func writePrivate(path string, data []byte) error { return writeCredentialFile(path, data) }
func readPrivate(path string) ([]byte, error) {
	f, err := openCredentialRecord(path)
	if err != nil {
		return nil, ErrStorage
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 128*1024+1))
	if err != nil || len(b) > 128*1024 {
		return nil, ErrStorage
	}
	return b, nil
}
