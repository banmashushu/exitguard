package guard

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"exitguard/internal/model"
)

const (
	maxRemoteProfiles = 32
	maxProfileLibrary = 128 << 10
)

var errProfileStorage = errors.New("本机代理配置库无法读取或更新；入口保持关闭，请检查文件权限或重新选择保存的代理")
var errProfileSelectionRequired = errors.New("已检测到保存的代理；原代理保持关闭，请完成导入并明确选择要使用的代理")

// A single atomic record binds each profile's route and its account. Config
// stores only the selected identity; its remote fields are runtime snapshots.
type remoteProfileRecord struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	ProxyURL    string   `json:"proxyURL"`
	ExpectedIPs []string `json:"expectedIPs"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
}

type profileLibrary struct {
	Version  int                   `json:"version"`
	Profiles []remoteProfileRecord `json:"profiles"`
}

func publicProfile(p remoteProfileRecord) model.RemoteProfile {
	return model.RemoteProfile{ID: p.ID, Name: p.Name, ProxyURL: p.ProxyURL, ExpectedIPs: append([]string{}, p.ExpectedIPs...), HasCredentials: p.Username != ""}
}

func validProfileID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func validateProfile(p remoteProfileRecord) error {
	if !validProfileID(p.ID) || strings.TrimSpace(p.Name) == "" || len(p.Name) > 120 || !utf8.ValidString(p.Name) {
		return errors.New("请填写有效的代理名称（最多 120 字节）")
	}
	for _, r := range p.Name {
		if unicode.IsControl(r) {
			return errors.New("代理名称不能包含控制字符")
		}
	}
	if p.ProxyURL == "" || len(p.ProxyURL) > 2048 {
		return errors.New("请填写远程代理服务器和端口")
	}
	c := defaults(model.Config{Mode: "remote", EnforcementMode: "proxy-only", ProxyURL: p.ProxyURL, ExpectedIPs: p.ExpectedIPs})
	if err := validateConfig(c, false); err != nil {
		return err
	}
	return validateProxyCredentials(p.Username, p.Password)
}

// Reject duplicate, unknown, null and absent members before decoding values.
// encoding/json's struct decoder alone would accept duplicate and null fields.
func strictProfileObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errProfileStorage
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !slices.Contains(keys, name) || fields[name] != nil {
			return nil, errProfileStorage
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errProfileStorage
		}
		fields[name] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(fields) != len(keys) {
		return nil, errProfileStorage
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errProfileStorage
	}
	return fields, nil
}

func readProfileLibrary(path string) (profileLibrary, error) {
	empty := profileLibrary{Version: 1, Profiles: []remoteProfileRecord{}}
	if !credentialPersistenceSupported {
		return empty, errProfileStorage
	}
	f, err := openCredentialRecord(path)
	if err != nil {
		if os.IsNotExist(err) {
			return empty, os.ErrNotExist
		}
		return empty, errProfileStorage
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > maxProfileLibrary {
		return empty, errProfileStorage
	}
	data, err := io.ReadAll(io.LimitReader(f, maxProfileLibrary+1))
	if err != nil || len(data) > maxProfileLibrary {
		return empty, errProfileStorage
	}
	fields, err := strictProfileObject(data, "version", "profiles")
	if err != nil {
		return empty, err
	}
	var version int
	var records []json.RawMessage
	if json.Unmarshal(fields["version"], &version) != nil || version != 1 || json.Unmarshal(fields["profiles"], &records) != nil || len(records) > maxRemoteProfiles {
		return empty, errProfileStorage
	}
	seen := make(map[string]bool, len(records))
	for _, raw := range records {
		fields, err := strictProfileObject(raw, "id", "name", "proxyURL", "expectedIPs", "username", "password")
		if err != nil {
			return empty, errProfileStorage
		}
		var p remoteProfileRecord
		if json.Unmarshal(raw, &p) != nil || validateProfile(p) != nil || seen[p.ID] {
			return empty, errProfileStorage
		}
		// A null array element is another partial value encoding/json accepts.
		var ips []json.RawMessage
		if json.Unmarshal(fields["expectedIPs"], &ips) != nil {
			return empty, errProfileStorage
		}
		for _, ip := range ips {
			if bytes.Equal(bytes.TrimSpace(ip), []byte("null")) {
				return empty, errProfileStorage
			}
		}
		seen[p.ID] = true
		empty.Profiles = append(empty.Profiles, p)
	}
	return empty, nil
}

func writeProfileLibrary(path string, library profileLibrary) error {
	if !credentialPersistenceSupported || library.Version != 1 || library.Profiles == nil || len(library.Profiles) > maxRemoteProfiles {
		return errProfileStorage
	}
	seen := make(map[string]bool, len(library.Profiles))
	for _, p := range library.Profiles {
		if validateProfile(p) != nil || p.ExpectedIPs == nil || seen[p.ID] {
			return errProfileStorage
		}
		seen[p.ID] = true
	}
	data, err := json.Marshal(library)
	if err != nil || len(data)+1 > maxProfileLibrary {
		return errProfileStorage
	}
	if writeCredentialFile(path, append(data, '\n')) != nil {
		return errProfileStorage
	}
	return nil
}

func (s *Service) profilesLocked() (profileLibrary, error) {
	lib, err := readProfileLibrary(s.configPath + ".profiles.json")
	if os.IsNotExist(err) && s.config.RemoteProfileID == "" && s.profileError == nil {
		return lib, nil
	}
	if err != nil {
		return lib, s.profileFailureLocked()
	}
	return lib, nil
}

func (s *Service) profileFailureLocked() error {
	return s.profileBlockedLocked(errProfileStorage)
}

func (s *Service) profileBlockedLocked(err error) error {
	s.closeLocked()
	s.profileError = err
	s.status.State, s.status.Reason = "blocked", err.Error()
	s.status.ObservedIP = ""
	s.eventLocked(s.status.Reason)
	return err
}

func (s *Service) profileInputFailureLocked(err error) error {
	s.closeLocked()
	s.status.State, s.status.Reason = "blocked", err.Error()
	s.eventLocked(s.status.Reason)
	return err
}

func (s *Service) RemoteProfiles() ([]model.RemoteProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lib, err := s.profilesLocked()
	if err != nil {
		return nil, err
	}
	profiles := make([]model.RemoteProfile, 0, len(lib.Profiles))
	for _, p := range lib.Profiles {
		profiles = append(profiles, publicProfile(p))
	}
	return profiles, nil
}

func profileIndex(lib profileLibrary, id string) int {
	return slices.IndexFunc(lib.Profiles, func(p remoteProfileRecord) bool { return p.ID == id })
}

func (s *Service) SaveRemoteProfile(input model.RemoteProfileInput) (model.RemoteProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inputFailure := func(err error) (model.RemoteProfile, error) {
		if input.ID != "" && input.ID == s.config.RemoteProfileID {
			err = s.profileInputFailureLocked(err)
		}
		return model.RemoteProfile{}, err
	}
	lib, err := s.profilesLocked()
	if err != nil {
		return model.RemoteProfile{}, err
	}
	idx := profileIndex(lib, input.ID)
	var old remoteProfileRecord
	if input.ID != "" && idx < 0 {
		return inputFailure(errors.New("保存的代理不存在，请重新选择"))
	}
	if idx >= 0 {
		old = lib.Profiles[idx]
	} else {
		if len(lib.Profiles) >= maxRemoteProfiles {
			return inputFailure(errors.New("最多保存 32 个独立代理，请先删除不再使用的配置"))
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return model.RemoteProfile{}, s.profileFailureLocked()
		}
		input.ID = hex.EncodeToString(nonce[:])
	}
	p := remoteProfileRecord{ID: input.ID, Name: strings.TrimSpace(input.Name), ProxyURL: strings.TrimSpace(input.ProxyURL), ExpectedIPs: append([]string{}, input.ExpectedIPs...)}
	switch input.CredentialAction {
	case "keep":
		if input.Username != "" || input.Password != "" {
			err = errors.New("保留账户时请清空账户输入框，或选择替换账户")
		} else if old.Username != "" && old.ProxyURL != p.ProxyURL {
			err = errors.New("更改服务器后不能沿用旧账户，请重新填写或清除账户")
		} else {
			p.Username, p.Password = old.Username, old.Password
		}
	case "replace":
		if input.Username == "" || input.Password == "" {
			err = errors.New("替换账户时请同时填写用户名和密码")
		} else {
			p.Username, p.Password = input.Username, input.Password
		}
	case "clear":
		if input.Username != "" || input.Password != "" {
			err = errors.New("清除账户时请清空用户名和密码输入框")
		}
	default:
		err = errors.New("请选择保留、替换或清除代理账户")
	}
	if err == nil {
		err = validateProfile(p)
	}
	if err != nil {
		return inputFailure(err)
	}
	active := s.config.RemoteProfileID == p.ID
	if active {
		s.closeLocked()
	}
	if idx >= 0 {
		lib.Profiles[idx] = p
	} else {
		lib.Profiles = append(lib.Profiles, p)
	}
	if err := writeProfileLibrary(s.configPath+".profiles.json", lib); err != nil {
		return model.RemoteProfile{}, s.profileFailureLocked()
	}
	if active {
		s.applyProfileLocked(p, false)
		if err := s.clearLegacyProfileCredentialsLocked(); err != nil {
			return model.RemoteProfile{}, err
		}
		s.profileUpdatedLocked("当前代理已保存，请重新检查出口并手动启动")
	}
	return publicProfile(p), nil
}

func (s *Service) applyProfileLocked(p remoteProfileRecord, restored bool) {
	s.config.Mode, s.config.RemoteProfileID = "remote", p.ID
	s.config.ProxyURL, s.config.ExpectedIPs = p.ProxyURL, append([]string{}, p.ExpectedIPs...)
	s.proxyUsername, s.proxyPassword = p.Username, p.Password
	s.status.UpstreamCredentialsSet = p.Username != ""
	s.status.UpstreamCredentialsSaved = p.Username != ""
	s.status.UpstreamCredentialsRestored = restored && p.Username != ""
	s.profileError = nil
}

func (s *Service) profileUpdatedLocked(reason string) {
	s.status.State, s.status.Reason = "unconfigured", reason
	s.status.ObservedIP, s.status.CheckedAt = "", ""
	s.status.EnforcementMode, s.status.ProxyAddress = s.config.EnforcementMode, proxyAddress(s.config)
	s.eventLocked(reason)
}

func (s *Service) SelectRemoteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	if id == "" {
		return s.detachProfileLocked()
	}
	lib, err := s.profilesLocked()
	if err != nil {
		return err
	}
	idx := profileIndex(lib, id)
	if idx < 0 {
		return s.profileInputFailureLocked(errors.New("保存的代理不存在，请重新选择"))
	}
	p := lib.Profiles[idx]
	c := copyConfig(s.config)
	c.Mode, c.RemoteProfileID, c.ProxyURL, c.ExpectedIPs = "remote", p.ID, p.ProxyURL, append([]string{}, p.ExpectedIPs...)
	if err := persistConfig(s.configPath, c); err != nil {
		return s.profileFailureLocked()
	}
	s.config = c
	s.applyProfileLocked(p, false)
	if err := s.clearLegacyProfileCredentialsLocked(); err != nil {
		return err
	}
	s.profileUpdatedLocked("已切换当前代理，请重新检查出口并手动启动")
	return nil
}

func (s *Service) detachProfileLocked() error {
	c := copyConfig(s.config)
	c.RemoteProfileID, c.ProxyURL, c.ExpectedIPs = "", "", nil
	if err := persistConfig(s.configPath, c); err != nil {
		return s.profileFailureLocked()
	}
	s.config = c
	s.proxyUsername, s.proxyPassword = "", ""
	s.status.UpstreamCredentialsSet, s.status.UpstreamCredentialsSaved, s.status.UpstreamCredentialsRestored = false, false, false
	if err := s.clearLegacyProfileCredentialsLocked(); err != nil {
		return err
	}
	s.profileError = nil
	s.profileUpdatedLocked("已取消使用当前代理，请选择代理并重新检查")
	return nil
}

func (s *Service) DeleteRemoteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lib, err := s.profilesLocked()
	if err != nil {
		return err
	}
	idx := profileIndex(lib, id)
	if idx < 0 {
		err := errors.New("保存的代理不存在，请重新选择")
		if id == s.config.RemoteProfileID {
			return s.profileInputFailureLocked(err)
		}
		return err
	}
	active := s.config.RemoteProfileID == id
	if active {
		s.closeLocked()
		// Detach first. A crash or failed library write can leave an unselected,
		// recoverable profile, but never a reference to an already-deleted pair.
		if err := s.detachProfileLocked(); err != nil {
			return err
		}
	}
	lib.Profiles = append(lib.Profiles[:idx:idx], lib.Profiles[idx+1:]...)
	if err := writeProfileLibrary(s.configPath+".profiles.json", lib); err != nil {
		return s.profileFailureLocked()
	}
	if active {
		s.profileError = nil
		s.profileUpdatedLocked("当前代理已删除，请选择其他保存的代理")
	}
	return nil
}

// initializeProfiles restores only an explicitly selected identity. It never
// falls back to legacy credentials if its library or record cannot be read.
func (s *Service) initializeProfiles() {
	lib, err := readProfileLibrary(s.configPath + ".profiles.json")
	if s.config.RemoteProfileID != "" {
		idx := profileIndex(lib, s.config.RemoteProfileID)
		if err != nil || idx < 0 {
			s.config.ProxyURL, s.config.ExpectedIPs = "", nil
			s.proxyUsername, s.proxyPassword = "", ""
			s.status.UpstreamCredentialsSet, s.status.UpstreamCredentialsSaved, s.status.UpstreamCredentialsRestored = false, false, false
			s.profileFailureLocked()
			return
		}
		s.applyProfileLocked(lib.Profiles[idx], true)
		s.status.Reason = "已恢复当前代理配置；请检查出口并手动启动"
		return
	}
	return
}

// EnsureRemoteProfiles performs the native UI's explicit one-time migration.
// Even a partial legacy remote setup becomes a draft; existing libraries,
// including empty ones, are never silently overwritten or merged on startup.
func (s *Service) EnsureRemoteProfiles() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lib, err := readProfileLibrary(s.configPath + ".profiles.json")
	if err == nil {
		if s.config.RemoteProfileID != "" {
			idx := profileIndex(lib, s.config.RemoteProfileID)
			if idx < 0 {
				return s.profileFailureLocked()
			}
			if err := s.clearLegacyProfileCredentialsLocked(); err != nil {
				return err
			}
			if s.profileError != nil {
				s.closeLocked()
				s.applyProfileLocked(lib.Profiles[idx], true)
				s.profileUpdatedLocked("代理配置已重新加载，请检查出口并手动启动")
			}
		} else {
			return s.settleUnselectedProfilesLocked(lib)
		}
		return nil
	}
	if !os.IsNotExist(err) || s.config.RemoteProfileID != "" {
		return s.profileFailureLocked()
	}
	s.closeLocked()
	if s.config.Mode != "remote" || s.config.ProxyURL == "" || validateConfig(s.config, false) != nil {
		if err := writeProfileLibrary(s.configPath+".profiles.json", lib); err != nil {
			return s.profileFailureLocked()
		}
		s.profileError = nil
		return nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return s.profileFailureLocked()
	}
	p := remoteProfileRecord{ID: hex.EncodeToString(nonce[:]), Name: "当前代理", ProxyURL: s.config.ProxyURL, ExpectedIPs: append([]string{}, s.config.ExpectedIPs...)}
	// Malformed or mismatched legacy accounts need explicit repair; do not
	// convert them into an account-less profile that masks the storage issue.
	account, err := readCredentialRecord(s.configPath + ".credentials.json")
	if err == nil {
		if account.ProxyURL != p.ProxyURL {
			return s.profileInputFailureLocked(errors.New("已保存账户与当前服务器不匹配，请重新保存或清除账户后重试导入"))
		}
		p.Username, p.Password = account.Username, account.Password
	} else if !os.IsNotExist(err) {
		return s.profileFailureLocked()
	}
	lib.Profiles = append(lib.Profiles, p)
	if err := writeProfileLibrary(s.configPath+".profiles.json", lib); err != nil {
		return s.profileFailureLocked()
	}
	c := copyConfig(s.config)
	c.RemoteProfileID = p.ID
	if err := persistConfig(s.configPath, c); err != nil {
		// Both legacy files and the recoverable newly created profile survive.
		// Restart sees a library and therefore does not migrate a second copy.
		return s.profileFailureLocked()
	}
	s.config = c
	s.applyProfileLocked(p, true)
	if err := s.clearLegacyProfileCredentialsLocked(); err != nil {
		return err
	}
	s.status.Reason = "已将原代理保存为当前代理；请检查出口并手动启动"
	return nil
}

// A library can be durable before its first selected reference is durable.
// Reconcile that interrupted cutover without selecting a profile or leaving
// the legacy route as a second, hidden source of active configuration.
func (s *Service) settleUnselectedProfilesLocked(lib profileLibrary) error {
	if s.config.Mode != "remote" {
		return nil
	}
	legacy, accountErr := readCredentialRecord(s.configPath + ".credentials.json")
	if accountErr != nil && !os.IsNotExist(accountErr) {
		return s.profileFailureLocked()
	}
	hasLegacyAccount := accountErr == nil
	hasLegacyRoute := s.config.Mode == "remote" && s.config.ProxyURL != ""
	if !hasLegacyRoute && !hasLegacyAccount {
		if s.profileError != nil {
			s.closeLocked()
			s.profileError = nil
			s.profileUpdatedLocked("代理配置库已加载，请明确选择要使用的代理")
		}
		return nil
	}
	s.closeLocked()
	if hasLegacyRoute && !slices.ContainsFunc(lib.Profiles, func(p remoteProfileRecord) bool {
		return p.ProxyURL == s.config.ProxyURL && slices.Equal(p.ExpectedIPs, s.config.ExpectedIPs) && p.Username == s.proxyUsername && p.Password == s.proxyPassword
	}) {
		// Do not erase a legacy config that the existing user library does not
		// fully represent, and never silently merge into or overwrite that library.
		return s.profileBlockedLocked(errProfileSelectionRequired)
	}
	if hasLegacyAccount && !slices.ContainsFunc(lib.Profiles, func(p remoteProfileRecord) bool {
		return p.ProxyURL == legacy.ProxyURL && p.Username == legacy.Username && p.Password == legacy.Password
	}) {
		return s.profileBlockedLocked(errProfileSelectionRequired)
	}
	if hasLegacyRoute {
		c := copyConfig(s.config)
		c.ProxyURL, c.ExpectedIPs = "", nil
		if err := persistConfig(s.configPath, c); err != nil {
			return s.profileFailureLocked()
		}
		s.config = c
	}
	s.proxyUsername, s.proxyPassword = "", ""
	s.status.UpstreamCredentialsSet, s.status.UpstreamCredentialsSaved, s.status.UpstreamCredentialsRestored = false, false, false
	if hasLegacyAccount {
		if err := s.clearLegacyProfileCredentialsLocked(); err != nil {
			return err
		}
	}
	s.profileError = nil
	s.profileUpdatedLocked("原代理已保存在代理配置库，请明确选择要使用的代理")
	return nil
}

// Only call after a selected reference (or an explicit detach) is durable.
// Keeping the old account through earlier cutover failures preserves recovery;
// removing it afterwards prevents a cleared/deleted profile leaving a password
// copy that the public credential flags can no longer account for.
func (s *Service) clearLegacyProfileCredentialsLocked() error {
	if removeCredentialRecord(s.configPath+".credentials.json") != nil {
		return s.profileFailureLocked()
	}
	return nil
}
