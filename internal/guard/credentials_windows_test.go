package guard

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func windowsCredentialFixture(t *testing.T, path, permissions string) {
	t.Helper()
	user, err := credentialUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sddl, _ := syscall.UTF16PtrFromString("O:" + user + permissions)
	var descriptor uintptr
	ok, _, _ := credentialConvertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		t.Fatal("fixture security descriptor creation failed")
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	sa := &syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, syscall.GENERIC_WRITE, 0, sa, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), path)
	if _, err = f.WriteString(`{"version":1,"proxyURL":"https://proxy.example:8443","username":"fixture-user","password":"fixture-password"}`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCredentialRenameRepairsACLAndRetainsPrivateHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	windowsCredentialFixture(t, path, "D:P(A;;FA;;;WD)")
	if _, err := readCredentialRecord(path); err == nil {
		t.Fatal("Everyone DACL accepted for a secret read")
	}
	want := credentialRecord{Version: 1, ProxyURL: "https://proxy.example:8443", Username: "replacement-user", Password: "replacement-password"}
	if err := writeCredentialRecord(path, want); err != nil {
		t.Fatal(err)
	}
	f, err := openCredentialRecord(path)
	if err != nil {
		t.Fatal("renamed account did not retain its private DACL")
	}
	if !credentialPrivateHandle(syscall.Handle(f.Fd())) {
		t.Fatal("replacement retained an old destination ACL")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("opened read handle allowed its target to be renamed")
	}
	f.Close()
	got, err := readCredentialRecord(path)
	if err != nil || got != want {
		t.Fatal("replacement record round trip failed")
	}
	if err = removeCredentialRecord(path); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("handle deletion did not remove the record")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary account file left behind")
	}
}

func TestWindowsCredentialRejectsUnprotectedAndExtraPrincipalDACL(t *testing.T) {
	user, err := credentialUserSID()
	if err != nil {
		t.Fatal(err)
	}
	for name, permissions := range map[string]string{
		"unprotected":     "D:(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)",
		"extra-principal": "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
		"incomplete":      "D:P(A;;FA;;;" + user + ")",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "account.json")
			windowsCredentialFixture(t, path, permissions)
			if _, err := readCredentialRecord(path); err == nil {
				t.Fatal("unattested DACL accepted")
			}
			if err := removeCredentialRecord(path); err != nil {
				t.Fatal("unsafe old ACL could not be explicitly cleared")
			}
		})
	}
}

func TestWindowsCredentialRejectsDeviceNetworkADSAndNonregularTargets(t *testing.T) {
	for _, path := range []string{`\\server\share\secret.json`, `\\?\C:\secret.json`, `\\.\pipe\secret`, `C:\secret.json:stream`, `C:secret.json`, `C:\NUL`, `C:\COM¹.txt`, `C:\folder.\secret.json`} {
		if _, err := credentialLocalPath(path); err == nil {
			t.Fatalf("unsafe path accepted: %q", path)
		}
		if err := removeCredentialRecord(path); err == nil || strings.Contains(err.Error(), path) {
			t.Fatal("unsafe path removal accepted or exposed its path")
		}
	}
	path := filepath.Join(t.TempDir(), "account.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCredentialFile(path, []byte("fixture")); err == nil {
		t.Fatal("directory overwritten")
	}
	if err := removeCredentialRecord(path); err == nil {
		t.Fatal("directory removed")
	}
}

func TestWindowsCredentialRejectsHardlinksAndReparseTargets(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "account.json")
	want := credentialRecord{Version: 1, ProxyURL: "https://proxy.example:8443", Username: "fixture-user", Password: "fixture-password"}
	if err := writeCredentialRecord(path, want); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(root, "hard.json")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialRecord(hard); err == nil {
		t.Fatal("hardlinked credential read")
	}
	if err := removeCredentialRecord(hard); err == nil {
		t.Fatal("hardlinked credential cleared")
	}
	if err := writeCredentialRecord(hard, want); err == nil {
		t.Fatal("hardlinked credential replaced")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("Windows symlink creation unavailable; reparse runtime check remains required")
	}
	if _, err := readCredentialRecord(link); err == nil {
		t.Fatal("reparse target read")
	}
	if err := writeCredentialRecord(link, want); err == nil {
		t.Fatal("reparse target replaced")
	}
	if err := removeCredentialRecord(link); err == nil {
		t.Fatal("reparse target cleared")
	}
	parent := filepath.Join(t.TempDir(), "linked-dir")
	if err := os.Symlink(root, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialRecord(filepath.Join(parent, "account.json")); err == nil {
		t.Fatal("reparse ancestor read")
	}
}

func TestWindowsCredentialParentHandlesPreventRename(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(parent, "account.json")
	_, locked, err := lockCredentialParents(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.close()
	if err := os.Rename(parent, parent+".moved"); err == nil {
		t.Fatal("validated ancestor renamed while locked")
	}
}
