//go:build windows && amd64

package nativeapp

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// This test is compiled on macOS and must be executed on Windows before ACL
// behavior is called verified. A broad inherited read ACE would fail it.
func TestNativeBackupHasProtectedDACLBeforeContentWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-backup.bak")
	file, err := privateBackup(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	name, _ := syscall.UTF16PtrFromString(path)
	advapi := syscall.NewLazyDLL("advapi32.dll")
	var needed uint32
	advapi.NewProc("GetFileSecurityW").Call(uintptr(unsafe.Pointer(name)), 4, 0, 0, uintptr(unsafe.Pointer(&needed)))
	buffer := make([]byte, needed)
	ok, _, err := advapi.NewProc("GetFileSecurityW").Call(uintptr(unsafe.Pointer(name)), 4, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		t.Fatal(err)
	}
	var result *uint16
	var textSize uint32
	ok, _, err = advapi.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW").Call(uintptr(unsafe.Pointer(&buffer[0])), 1, 4, uintptr(unsafe.Pointer(&result)), uintptr(unsafe.Pointer(&textSize)))
	if ok == 0 {
		t.Fatal(err)
	}
	defer syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree").Call(uintptr(unsafe.Pointer(result)))
	if textSize == 0 || textSize > 4096 {
		t.Fatal("invalid SDDL output length")
	}
	data := unsafe.Slice(result, int(textSize))
	end := 0
	for data[end] != 0 {
		end++
	}
	sddl := syscall.UTF16ToString(data[:end])
	if !strings.Contains(sddl, "D:P") || strings.Count(sddl, "(A;") != 3 || !strings.Contains(sddl, ";;;SY)") || !strings.Contains(sddl, ";;;BA)") || !strings.Contains(sddl, ";;;OW)") {
		t.Fatalf("unrestricted backup ACL before first write: %s", sddl)
	}
	if _, err := file.Write([]byte("private-fixture")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := privateBackup(path); err == nil {
		t.Fatal("backup overwrote existing file")
	}
}
