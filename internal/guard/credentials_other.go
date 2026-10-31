//go:build !darwin && !windows

package guard

import "os"

// POSIX mode bits cannot attest to a private Windows DACL. Keep session-only
// credentials usable until a platform-specific private store is implemented.
const credentialPersistenceSupported = false

func privateCredentialInfo(os.FileInfo) bool         { return false }
func openPrivateCredential(string) (*os.File, error) { return nil, errCredentialStorage }
