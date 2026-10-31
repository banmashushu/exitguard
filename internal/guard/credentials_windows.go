package guard

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const credentialPersistenceSupported = true

const (
	credentialReadControl = 0x00020000
	credentialDelete      = 0x00010000
	credentialAllAccess   = 0x001f01ff
)

var (
	credentialKernel32     = syscall.NewLazyDLL("kernel32.dll")
	credentialAdvapi32     = syscall.NewLazyDLL("advapi32.dll")
	credentialDriveType    = credentialKernel32.NewProc("GetDriveTypeW")
	credentialSetFileInfo  = credentialKernel32.NewProc("SetFileInformationByHandle")
	credentialSecurityInfo = credentialAdvapi32.NewProc("GetSecurityInfo")
	credentialSDControl    = credentialAdvapi32.NewProc("GetSecurityDescriptorControl")
	credentialConvertSD    = credentialAdvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	credentialGetACLInfo   = credentialAdvapi32.NewProc("GetAclInformation")
	credentialGetACE       = credentialAdvapi32.NewProc("GetAce")
)

// Only ordinary local drive paths are accepted. In particular, a rooted path
// does not imply a local disk: mapped drives are checked separately below.
func credentialLocalPath(path string) (string, error) {
	if len(path) < 4 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` || strings.ContainsAny(path, "/\x00") {
		return "", errCredentialStorage
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part || strings.ContainsAny(part, `:<>"|?*`) {
			return "", errCredentialStorage
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		deviceNumber := strings.TrimPrefix(strings.TrimPrefix(base, "COM"), "LPT")
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (deviceNumber != base && strings.Contains("|1|2|3|4|5|6|7|8|9|¹|²|³|", "|"+deviceNumber+"|")) {
			return "", errCredentialStorage
		}
	}
	return filepath.Clean(path), nil
}

func credentialUserSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", errCredentialStorage
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", errCredentialStorage
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return "", errCredentialStorage
	}
	return sid, nil
}

func credentialSecurityAttributes() (*syscall.SecurityAttributes, func(), error) {
	sid, err := credentialUserSID()
	if err != nil {
		return nil, nil, err
	}
	text, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, nil, errCredentialStorage
	}
	var sd uintptr
	ok, _, _ := credentialConvertSD.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if ok == 0 {
		return nil, nil, errCredentialStorage
	}
	sa := &syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	return sa, func() { _, _ = syscall.LocalFree(syscall.Handle(sd)) }, nil
}

// Every ancestor remains open without FILE_SHARE_DELETE throughout the
// operation. Thus a validated parent cannot be renamed into a reparse path
// between validation and the following file open/rename/delete.
type credentialParents []syscall.Handle

func (p credentialParents) close() {
	for i := len(p) - 1; i >= 0; i-- {
		_ = syscall.CloseHandle(p[i])
	}
}

func lockCredentialParents(path string, create bool) (string, credentialParents, error) {
	path, err := credentialLocalPath(path)
	if err != nil {
		return "", nil, err
	}
	root := path[:3]
	r, _ := syscall.UTF16PtrFromString(root)
	drive, _, _ := credentialDriveType.Call(uintptr(unsafe.Pointer(r)))
	if drive != 3 {
		return "", nil, errCredentialStorage
	} // DRIVE_FIXED; rejects mapped/network/unknown volumes.
	var parents credentialParents
	current := root
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), root), `\`)
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			if parts[i] == "" {
				continue
			}
			current = filepath.Join(current, parts[i])
		}
		p, _ := syscall.UTF16PtrFromString(current)
		// LIST_DIRECTORY | TRAVERSE | READ_ATTRIBUTES also permits the final
		// directory handle to serve as FileRenameInfo.RootDirectory.
		const directoryAccess = 0x01 | 0x20 | 0x80
		h, e := syscall.CreateFile(p, directoryAccess, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if (e == syscall.ERROR_FILE_NOT_FOUND || e == syscall.ERROR_PATH_NOT_FOUND) && create {
			sa, free, se := credentialSecurityAttributes()
			if se != nil {
				parents.close()
				return "", nil, se
			}
			se = syscall.CreateDirectory(p, sa)
			free()
			if se == nil || se == syscall.ERROR_ALREADY_EXISTS {
				h, e = syscall.CreateFile(p, directoryAccess, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
			}
		}
		if e != nil {
			parents.close()
			if !create && (e == syscall.ERROR_FILE_NOT_FOUND || e == syscall.ERROR_PATH_NOT_FOUND) {
				return "", nil, os.ErrNotExist
			}
			return "", nil, errCredentialStorage
		}
		parents = append(parents, h)
		var info syscall.ByHandleFileInformation
		if syscall.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
			parents.close()
			return "", nil, errCredentialStorage
		}
	}
	return path, parents, nil
}

func credentialRegularHandle(h syscall.Handle) bool {
	var info syscall.ByHandleFileInformation
	kind, err := syscall.GetFileType(h)
	return err == nil && kind == syscall.FILE_TYPE_DISK && syscall.GetFileInformationByHandle(h, &info) == nil && info.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) == 0 && info.NumberOfLinks == 1
}

// This verifies the descriptor of the same handle used for secret reads.
// Accept only our explicit protected DACL; POSIX permission bits are irrelevant.
func credentialPrivateHandle(h syscall.Handle) bool {
	user, err := credentialUserSID()
	if err != nil {
		return false
	}
	var owner *syscall.SID
	var acl, sd uintptr
	status, _, _ := credentialSecurityInfo.Call(uintptr(h), 1, 1|4, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&sd)))
	if status != 0 || sd == 0 {
		return false
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil || acl == 0 {
		return false
	}
	ownerSID, err := owner.String()
	if err != nil || ownerSID != user {
		return false
	}
	var control uint16
	var revision uint32
	ok, _, _ := credentialSDControl.Call(sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || control&0x1004 != 0x1004 {
		return false
	} // SE_DACL_PROTECTED | SE_DACL_PRESENT
	var info struct{ Count, InUse, Free uint32 }
	ok, _, _ = credentialGetACLInfo.Call(acl, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 2)
	if ok == 0 || info.Count != 3 {
		return false
	}
	allowed := map[string]bool{user: true, "S-1-5-18": true, "S-1-5-32-544": true}
	for i := uint32(0); i < info.Count; i++ {
		var ace unsafe.Pointer
		ok, _, _ = credentialGetACE.Call(acl, uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 || ace == nil {
			return false
		}
		header := (*struct {
			Type, Flags uint8
			Size        uint16
			Mask        uint32
		})(ace)
		if header.Type != 0 || header.Flags != 0 || header.Size < 16 || header.Mask != credentialAllAccess {
			return false
		}
		sid, err := (*syscall.SID)(unsafe.Add(ace, 8)).String()
		if err != nil || !allowed[sid] {
			return false
		}
		delete(allowed, sid)
	}
	return len(allowed) == 0
}

func openCredentialRecord(path string) (*os.File, error) {
	path, parents, err := lockCredentialParents(path, false)
	if err != nil {
		return nil, err
	}
	defer parents.close()
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|credentialReadControl, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return nil, os.ErrNotExist
		}
		return nil, errCredentialStorage
	}
	if !credentialRegularHandle(h) || !credentialPrivateHandle(h) {
		_ = syscall.CloseHandle(h)
		return nil, errCredentialStorage
	}
	return os.NewFile(uintptr(h), path), nil
}

// Check an existing target without reading it. Replacement/clear may repair an
// old loose ACL, but may never operate on a reparse point or a nonregular file.
func checkCredentialReplacement(path string) error {
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, 0x80, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if err != nil {
		return errCredentialStorage
	}
	defer syscall.CloseHandle(h)
	if !credentialRegularHandle(h) {
		return errCredentialStorage
	}
	return nil
}

func writeCredentialFile(path string, data []byte) error {
	path, parents, err := lockCredentialParents(path, true)
	if err != nil {
		return errCredentialStorage
	}
	defer parents.close()
	if err = checkCredentialReplacement(path); err != nil {
		return err
	}
	sa, free, err := credentialSecurityAttributes()
	if err != nil {
		return err
	}
	defer free()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return errCredentialStorage
	}
	name := filepath.Join(filepath.Dir(path), ".exitguard-account-"+hex.EncodeToString(nonce[:]))
	p, _ := syscall.UTF16PtrFromString(name)
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE|credentialReadControl|credentialDelete, 0, sa, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errCredentialStorage
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	renamed := false
	defer func() {
		if !renamed {
			_ = deleteCredentialHandle(h)
		}
	}()
	if !credentialRegularHandle(h) || !credentialPrivateHandle(h) {
		return errCredentialStorage
	}
	if _, err = f.Write(data); err != nil {
		return errCredentialStorage
	}
	if err = f.Sync(); err != nil {
		return errCredentialStorage
	}
	if err = checkCredentialReplacement(path); err != nil {
		return err
	}
	// FileRenameInfo is a handle rename with a parent directory handle. It cannot
	// copy to a different volume or preserve an old destination's permissive ACL.
	if err = renameCredentialHandle(h, parents[len(parents)-1], filepath.Base(path)); err != nil {
		return err
	}
	if !credentialRegularHandle(h) || !credentialPrivateHandle(h) {
		return errCredentialStorage
	}
	renamed = true
	return nil
}

func renameCredentialHandle(h, parent syscall.Handle, name string) error {
	filename, err := syscall.UTF16FromString(name)
	if err != nil {
		return errCredentialStorage
	}
	filename = filename[:len(filename)-1]
	var layout struct {
		Replace uint32
		Parent  syscall.Handle
		Length  uint32
		Name    uint16
	}
	offset := unsafe.Offsetof(layout.Name)
	size := max(int(unsafe.Sizeof(layout)), int(offset)+(len(filename)+1)*2)
	buffer := make([]byte, size)
	info := (*struct {
		Replace uint32
		Parent  syscall.Handle
		Length  uint32
	})(unsafe.Pointer(&buffer[0]))
	info.Replace, info.Parent, info.Length = 1, parent, uint32(len(filename)*2)
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[offset])), len(filename)), filename)
	ok, _, _ := credentialSetFileInfo.Call(uintptr(h), 3, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	runtime.KeepAlive(buffer)
	if ok == 0 {
		return errCredentialStorage
	}
	return nil
}

func deleteCredentialHandle(h syscall.Handle) error {
	remove := byte(1)
	ok, _, _ := credentialSetFileInfo.Call(uintptr(h), 4, uintptr(unsafe.Pointer(&remove)), 1)
	if ok == 0 {
		return errCredentialStorage
	}
	return nil
}

func removeCredentialRecord(path string) error {
	path, parents, err := lockCredentialParents(path, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errCredentialStorage
	}
	defer parents.close()
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, credentialDelete|0x80, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if err != nil {
		return errCredentialStorage
	}
	defer syscall.CloseHandle(h)
	if !credentialRegularHandle(h) {
		return errCredentialStorage
	}
	return deleteCredentialHandle(h)
}
