package guard

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxCredentialRecord = 8 << 10

var errCredentialStorage = errors.New("本机账户文件无法读取或更新；请重新保存或清除，未能清除的数据可能仍保留")

// This record deliberately never belongs to model.Config or a UI response.
type credentialRecord struct {
	Version  int    `json:"version"`
	ProxyURL string `json:"proxyURL"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Resolve the owned directory without following user-created directory links.
// /var and /tmp are the two standard macOS links used by temporary directories.
func credentialDirectory(path string, create bool) (string, error) {
	full, err := filepath.Abs(path)
	if err != nil {
		return "", errCredentialStorage
	}
	dir := filepath.Dir(full)
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(dir, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) && create {
			if err = os.Mkdir(current, 0700); err == nil {
				info, err = os.Lstat(current)
			}
		}
		if err != nil {
			if os.IsNotExist(err) && !create {
				return "", os.ErrNotExist
			}
			return "", errCredentialStorage
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil || !((current == "/var" && resolved == "/private/var") || (current == "/tmp" && resolved == "/private/tmp")) {
				return "", errCredentialStorage
			}
			continue
		}
		if !info.IsDir() {
			return "", errCredentialStorage
		}
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", errCredentialStorage
	}
	return filepath.Join(resolved, filepath.Base(full)), nil
}

func credentialTarget(path string, private bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (private && !privateCredentialInfo(info)) {
		return nil, errCredentialStorage
	}
	return info, nil
}

func readCredentialRecord(path string) (credentialRecord, error) {
	var record credentialRecord
	path, err := credentialDirectory(path, false)
	if err != nil {
		return record, err
	}
	info, err := credentialTarget(path, true)
	if err != nil {
		if os.IsNotExist(err) {
			return record, os.ErrNotExist
		}
		return record, errCredentialStorage
	}
	if info.Size() > maxCredentialRecord {
		return record, errCredentialStorage
	}
	f, err := openPrivateCredential(path)
	if err != nil {
		return record, errCredentialStorage
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !privateCredentialInfo(opened) {
		return record, errCredentialStorage
	}
	d := json.NewDecoder(io.LimitReader(f, maxCredentialRecord+1))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return credentialRecord{}, errCredentialStorage
	}
	seen := make(map[string]bool, 4)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return credentialRecord{}, errCredentialStorage
		}
		seen[key] = true
		switch key {
		case "version":
			err = d.Decode(&record.Version)
		case "proxyURL":
			err = d.Decode(&record.ProxyURL)
		case "username":
			err = d.Decode(&record.Username)
		case "password":
			err = d.Decode(&record.Password)
		default:
			return credentialRecord{}, errCredentialStorage
		}
		if err != nil {
			return credentialRecord{}, errCredentialStorage
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return credentialRecord{}, errCredentialStorage
	}
	var extra any
	if d.Decode(&extra) != io.EOF || record.Version != 1 || record.Username == "" || validateProxyCredentials(record.Username, record.Password) != nil {
		return credentialRecord{}, errCredentialStorage
	}
	if _, err = remoteProxyURL(record.ProxyURL); err != nil {
		return credentialRecord{}, errCredentialStorage
	}
	return record, nil
}

func writeCredentialRecord(path string, record credentialRecord) error {
	path, err := credentialDirectory(path, true)
	if err != nil {
		return errCredentialStorage
	}
	if _, err = credentialTarget(path, false); err != nil && !os.IsNotExist(err) {
		return errCredentialStorage
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".exitguard-account-*")
	if err != nil {
		return errCredentialStorage
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(record)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errCredentialStorage
	}
	// A replacement must never follow a link that appeared while writing.
	if _, err = credentialTarget(path, false); err != nil && !os.IsNotExist(err) {
		return errCredentialStorage
	}
	if err = os.Rename(name, path); err != nil {
		return errCredentialStorage
	}
	return syncCredentialDirectory(dir)
}

func removeCredentialRecord(path string) error {
	path, err := credentialDirectory(path, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errCredentialStorage
	}
	if _, err = credentialTarget(path, false); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return errCredentialStorage
	}
	if err = os.Remove(path); err != nil {
		return errCredentialStorage
	}
	return syncCredentialDirectory(filepath.Dir(path))
}

func syncCredentialDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return errCredentialStorage
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return errCredentialStorage
	}
	return nil
}
