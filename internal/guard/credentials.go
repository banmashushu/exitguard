package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

func readCredentialRecord(path string) (credentialRecord, error) {
	var record credentialRecord
	f, err := openCredentialRecord(path)
	if err != nil {
		return record, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > maxCredentialRecord {
		return record, errCredentialStorage
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialRecord+1))
	if err != nil || len(data) > maxCredentialRecord {
		return record, errCredentialStorage
	}
	d := json.NewDecoder(bytes.NewReader(data))
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
	data, err := json.Marshal(record)
	if err != nil || len(data)+1 > maxCredentialRecord {
		return errCredentialStorage
	}
	return writeCredentialFile(path, append(data, '\n'))
}
