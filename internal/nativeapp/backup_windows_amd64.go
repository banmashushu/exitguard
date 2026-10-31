//go:build windows && amd64

package nativeapp

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// Windows ignores POSIX0600 for a new file's DACL. Pass a protected restrictive
// descriptor to CREATE_NEW instead: it applies before a single private byte is
// written. Only SYSTEM, Administrators and the file owner receive access.
func privateBackup(path string) (*os.File, error) {
	sddl, _ := syscall.UTF16PtrFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)")
	var descriptor uintptr
	ok, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 || descriptor == 0 {
		return nil, errors.New("无法建立私有 Windows 配置备份权限")
	}
	defer syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree").Call(descriptor)
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, &attributes, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("无法创建新的私有配置备份；未改动 INI")
	}
	return os.NewFile(uintptr(handle), path), nil
}
