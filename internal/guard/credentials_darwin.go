package guard

import (
	"os"
	"syscall"
)

const credentialPersistenceSupported = true

func privateCredentialInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && stat.Uid == uint32(os.Getuid())
}

func openPrivateCredential(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errCredentialStorage
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), path), nil
}
