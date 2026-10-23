//go:build windows && amd64

package enforce

// The ABI below follows the Windows SDK fwpmtypes.h/fwptypes.h x64 layout.
// This adapter deliberately supports x64 only until other ABIs are verified.
import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type wfpGUID struct {
	A    uint32
	B, C uint16
	D    [8]byte
}
type wfpDisplay struct{ Name, Description *uint16 }
type wfpBlob struct {
	Size uint32
	_    uint32
	Data *byte
}
type wfpValue struct {
	Type  uint32
	_     uint32
	Value uintptr
}
type wfpBlobValue struct {
	Type uint32
	_    uint32
	Blob *wfpBlob
}
type wfpCondition struct {
	Field wfpGUID
	Match uint32
	_     uint32
	Value wfpValue
}
type wfpAction struct {
	Type uint32
	Key  wfpGUID
}
type wfpFilter struct {
	Key             wfpGUID
	Display         wfpDisplay
	Flags           uint32
	_               uint32
	Provider        *wfpGUID
	Data            wfpBlob
	Layer, Sublayer wfpGUID
	Weight          wfpValue
	Count           uint32
	_               uint32
	Conditions      *wfpCondition
	Action          wfpAction
	_               uint32
	Context         [16]byte
	Reserved        *wfpGUID
	ID              uint64
	EffectiveWeight wfpValue
}
type wfpSublayer struct {
	Key      wfpGUID
	Display  wfpDisplay
	Flags    uint32
	_        uint32
	Provider *wfpGUID
	Data     wfpBlob
	Weight   uint16
	_        [6]byte
}

// Compile-time ABI checks: a layout regression must fail the native build.
var _ [200 - unsafe.Sizeof(wfpFilter{})]byte
var _ [unsafe.Sizeof(wfpFilter{}) - 200]byte
var _ [40 - unsafe.Sizeof(wfpCondition{})]byte
var _ [unsafe.Sizeof(wfpCondition{}) - 40]byte
var _ [72 - unsafe.Sizeof(wfpSublayer{})]byte
var _ [unsafe.Sizeof(wfpSublayer{}) - 72]byte

var (
	wfpSublayerKey = wfpGUID{0xdce48d1f, 0xcb78, 0x4c79, [8]byte{0xb9, 0x0e, 0xd0, 0x63, 0xae, 0xb0, 0x39, 0x13}}
	wfpConnect4    = wfpGUID{0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	wfpConnect6    = wfpGUID{0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	wfpAccept4     = wfpGUID{0xe1cd9fe7, 0xf4b5, 0x4273, [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	wfpAccept6     = wfpGUID{0xa3b42c97, 0x9f04, 0x4672, [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}
	wfpAppID       = wfpGUID{0xd78e1e87, 0x8644, 0x4ea5, [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	wfpAddress     = wfpGUID{0xb235ae9a, 0x1d64, 0x49b8, [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	wfpPort        = wfpGUID{0xc35a604d, 0xd22b, 0x4e1a, [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	wfpProtocol    = wfpGUID{0x3971ef2b, 0x623e, 0x4f9a, [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	wfpLoadOnce    sync.Once
	wfpLibrary     *syscall.DLL
	wfpLoadError   error
)

const wfpAlreadyExists = uintptr(0x80320009)
const wfpNotFound = uintptr(0x80320008)
const wfpSublayerNotFound = uintptr(0x80320007)

// Resolve the system directory through a KnownDLL rather than searching the
// current directory for fwpuclnt.dll.
func loadWFP() error {
	wfpLoadOnce.Do(func() {
		kernel := syscall.NewLazyDLL("kernel32.dll")
		var buffer [32768]uint16
		n, _, err := kernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if n == 0 || n >= uintptr(len(buffer)) {
			wfpLoadError = fmt.Errorf("Windows system directory unavailable: %v", err)
			return
		}
		wfpLibrary, wfpLoadError = syscall.LoadDLL(filepath.Join(syscall.UTF16ToString(buffer[:n]), "fwpuclnt.dll"))
	})
	return wfpLoadError
}

//go:uintptrescapes
func wfpCall(name string, args ...uintptr) (uintptr, error) {
	if err := loadWFP(); err != nil {
		return 0, err
	}
	proc, err := wfpLibrary.FindProc(name)
	if err != nil {
		return 0, err
	}
	result, _, _ := proc.Call(args...)
	if result != 0 {
		return result, fmt.Errorf("%s: Windows status 0x%08x (installation/removal requires administrator privileges)", name, result)
	}
	return result, nil
}
func wfpFree(pointer unsafe.Pointer) {
	if pointer != nil {
		_, _ = wfpCall("FwpmFreeMemory0", uintptr(unsafe.Pointer(&pointer)))
	}
}
func wfpOpen() (uintptr, error) {
	var handle uintptr
	_, err := wfpCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&handle)))
	return handle, err
}
func Supported() bool { return loadWFP() == nil }

func validateWindowsPolicy(p Policy) error {
	if len(p.BundleIDs) > 0 {
		return errors.New("Windows enforcement requires explicit executable paths; bundle identifiers are unsupported")
	}
	for _, program := range p.Programs {
		if !filepath.IsAbs(program) || filepath.VolumeName(program) == "" {
			return errors.New("Windows targets require absolute drive-qualified executable paths")
		}
		info, err := os.Stat(program)
		if err != nil {
			return fmt.Errorf("protected executable unavailable: %w", err)
		}
		if info.IsDir() {
			return errors.New("protected target must be an executable file")
		}
	}
	return nil
}

func blobFor(data []byte) wfpBlob {
	if len(data) == 0 {
		return wfpBlob{}
	}
	return wfpBlob{Size: uint32(len(data)), Data: &data[0]}
}
func blobBytes(blob wfpBlob) []byte {
	if blob.Size == 0 {
		return nil
	}
	if blob.Size > 1<<20 || blob.Data == nil {
		return nil
	}
	return unsafe.Slice(blob.Data, int(blob.Size))
}
func guidFromKey(key [16]byte) wfpGUID {
	return wfpGUID{binary.LittleEndian.Uint32(key[0:4]), binary.LittleEndian.Uint16(key[4:6]), binary.LittleEndian.Uint16(key[6:8]), [8]byte(key[8:16])}
}
func keyFromGUID(guid wfpGUID) (key [16]byte) {
	binary.LittleEndian.PutUint32(key[0:4], guid.A)
	binary.LittleEndian.PutUint16(key[4:6], guid.B)
	binary.LittleEndian.PutUint16(key[6:8], guid.C)
	copy(key[8:], guid.D[:])
	return
}
func layerFor(rule denyRule) wfpGUID {
	if rule.Inbound {
		if rule.Family == 6 {
			return wfpAccept6
		}
		return wfpAccept4
	}
	if rule.Family == 6 {
		return wfpConnect6
	}
	return wfpConnect4
}
func appBlob(program string) (*wfpBlob, error) {
	path, err := syscall.UTF16PtrFromString(program)
	if err != nil {
		return nil, err
	}
	var app *wfpBlob
	_, err = wfpCall("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&app)))
	runtime.KeepAlive(path)
	if err != nil {
		return nil, err
	}
	if app == nil || len(blobBytes(*app)) == 0 {
		return nil, errors.New("Windows returned an empty executable identity")
	}
	return app, nil
}
func nativeConditions(rule denyRule, app *wfpBlob) []wfpCondition {
	out := []wfpCondition{{Field: wfpAppID, Match: 0, Value: wfpValue{Type: 12, Value: uintptr(unsafe.Pointer(app))}}}
	for _, c := range rule.Conditions {
		v := wfpValue{Value: uintptr(c.Value)}
		var field wfpGUID
		switch c.Field {
		case "address":
			field = wfpAddress
			v.Type = 3
		case "port":
			field = wfpPort
			v.Type = 2
		case "protocol":
			field = wfpProtocol
			v.Type = 1
		}
		var match uint32
		if c.NotEqual {
			match = 10
		}
		out = append(out, wfpCondition{Field: field, Match: match, Value: v})
	}
	return out
}
func makeNativeFilter(rule denyRule, app *wfpBlob, hash string) (wfpFilter, []wfpCondition, []byte) {
	conditions := nativeConditions(rule, app)
	data := encodeRuleMetadata(rule, hash)
	name, _ := syscall.UTF16PtrFromString("ExitGuard protected executable restriction")
	filter := wfpFilter{Key: guidFromKey(rule.Key), Display: wfpDisplay{Name: name}, Flags: 1, Data: blobFor(data), Layer: layerFor(rule), Sublayer: wfpSublayerKey, Weight: wfpValue{Type: 1, Value: 15}, Count: uint32(len(conditions)), Conditions: &conditions[0], Action: wfpAction{Type: 0x1001}}
	return filter, conditions, data
}

func verifySublayer(handle uintptr) error {
	var sublayer *wfpSublayer
	if _, err := wfpCall("FwpmSubLayerGetByKey0", handle, uintptr(unsafe.Pointer(&wfpSublayerKey)), uintptr(unsafe.Pointer(&sublayer))); err != nil {
		return err
	}
	defer wfpFree(unsafe.Pointer(sublayer))
	if sublayer == nil || sublayer.Key != wfpSublayerKey || sublayer.Flags != 1 || sublayer.Provider != nil || string(blobBytes(sublayer.Data)) != wfpOwner || sublayer.Weight != 65535 {
		return errors.New("ExitGuard WFP sublayer does not match")
	}
	return nil
}

// No provider is associated: Microsoft documents providerless persistent
// objects as loaded when BFE starts, without an owning service dependency.
func addSublayer(handle uintptr) error {
	data := []byte(wfpOwner)
	name, _ := syscall.UTF16PtrFromString("ExitGuard")
	sub := wfpSublayer{Key: wfpSublayerKey, Display: wfpDisplay{Name: name}, Flags: 1, Data: blobFor(data), Weight: 65535}
	code, err := wfpCall("FwpmSubLayerAdd0", handle, uintptr(unsafe.Pointer(&sub)), 0)
	runtime.KeepAlive(sub)
	runtime.KeepAlive(data)
	if err != nil && code != wfpAlreadyExists {
		return err
	}
	return verifySublayer(handle)
}

func inspect(ctx context.Context, p Policy) (Proof, error) {
	proof := Proof{Reason: "Windows native filters are not verified"}
	if err := validateWindowsPolicy(p); err != nil {
		proof.Reason = err.Error()
		return proof, err
	}
	handle, err := wfpOpen()
	if err != nil {
		proof.Reason = err.Error()
		return proof, err
	}
	defer wfpCall("FwpmEngineClose0", handle)
	if _, err = wfpCall("FwpmTransactionBegin0", handle, 1); err != nil {
		return proof, err
	}
	defer wfpCall("FwpmTransactionAbort0", handle)
	if err = verifySublayer(handle); err != nil {
		proof.Reason = err.Error()
		return proof, err
	}
	rules := windowsRules(p)
	keys, err := ownedFilterKeys(ctx, handle)
	if err != nil {
		return proof, err
	}
	if !matchingNativeRuleSet(keys, rules) {
		return Proof{Reason: "native WFP rule set contains missing or unexpected filters"}, errors.New("native WFP rule set mismatch")
	}
	for _, rule := range rules {
		if err = ctx.Err(); err != nil {
			return proof, err
		}
		app, e := appBlob(rule.Program)
		if e != nil {
			return proof, e
		}
		err = inspectRule(handle, rule, app, Hash(p))
		wfpFree(unsafe.Pointer(app))
		if err != nil {
			proof.Reason = err.Error()
			return proof, err
		}
	}
	return Proof{Active: true, PolicyHash: Hash(p), Reason: "matching persistent WFP filters read from the Windows Base Filtering Engine; real-device traffic tests are still required"}, nil
}

func inspectRule(handle uintptr, rule denyRule, app *wfpBlob, hash string) error {
	key := guidFromKey(rule.Key)
	var actual *wfpFilter
	if _, err := wfpCall("FwpmFilterGetByKey0", handle, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&actual))); err != nil {
		return err
	}
	defer wfpFree(unsafe.Pointer(actual))
	return verifyNativeFilter(actual, rule, app, hash)
}

func verifyNativeFilter(actual *wfpFilter, rule denyRule, app *wfpBlob, hash string) error {
	key := guidFromKey(rule.Key)
	expected, conditions, data := makeNativeFilter(rule, app, hash)
	defer runtime.KeepAlive(data)
	if actual == nil || actual.Key != key || actual.Flags != 1 || actual.Provider != nil || actual.Sublayer != wfpSublayerKey || actual.Layer != expected.Layer || actual.Action.Type != 0x1001 || actual.Action.Key != (wfpGUID{}) || actual.Weight.Type != 1 || actual.Weight.Value != 15 || actual.Count != uint32(len(conditions)) || !bytes.Equal(blobBytes(actual.Data), data) || actual.Conditions == nil {
		return errors.New("native WFP rule missing, disabled or different from the requested policy")
	}
	read := unsafe.Slice(actual.Conditions, int(actual.Count))
	for i, want := range conditions {
		got := read[i]
		if got.Field != want.Field || got.Match != want.Match || got.Value.Type != want.Value.Type {
			return errors.New("native WFP condition identity/type mismatch")
		}
		if i == 0 {
			// Read the pointer arm of the native union directly. Converting its
			// numeric arm back to unsafe.Pointer would violate Go's pointer rules.
			blob := (*wfpBlobValue)(unsafe.Pointer(&got.Value)).Blob
			if blob == nil || !bytes.Equal(blobBytes(*blob), blobBytes(*app)) {
				return errors.New("native WFP executable identity mismatch")
			}
		} else if got.Value.Value != want.Value.Value {
			return errors.New("native WFP endpoint/protocol condition mismatch")
		}
	}
	return nil
}

func install(ctx context.Context, p Policy) error {
	if err := validateWindowsPolicy(p); err != nil {
		return err
	}
	if err := requireWindowsTargetsStopped(p); err != nil {
		return err
	}
	handle, err := wfpOpen()
	if err != nil {
		return err
	}
	defer wfpCall("FwpmEngineClose0", handle)
	if _, err = wfpCall("FwpmTransactionBegin0", handle, 0); err != nil {
		return err
	}
	defer wfpCall("FwpmTransactionAbort0", handle)
	if err = addSublayer(handle); err != nil {
		return err
	}
	if err = deleteOwnedFilters(ctx, handle); err != nil {
		return err
	}
	for _, rule := range windowsRules(p) {
		if err = ctx.Err(); err != nil {
			return err
		}
		app, e := appBlob(rule.Program)
		if e != nil {
			return e
		}
		filter, conditions, data := makeNativeFilter(rule, app, Hash(p))
		_, err = wfpCall("FwpmFilterAdd0", handle, uintptr(unsafe.Pointer(&filter)), 0, 0)
		runtime.KeepAlive(conditions)
		runtime.KeepAlive(data)
		runtime.KeepAlive(filter)
		wfpFree(unsafe.Pointer(app))
		if err != nil {
			return err
		}
	}
	_, err = wfpCall("FwpmTransactionCommit0", handle)
	return err
}

func requireWindowsTargetsStopped(p Policy) error {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("cannot inspect target process startup state: %w", err)
	}
	defer syscall.CloseHandle(snapshot)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = syscall.Process32First(snapshot, &entry)
	for err == nil {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		for _, program := range p.Programs {
			if !strings.EqualFold(name, filepath.Base(program)) {
				continue
			}
			process, e := syscall.OpenProcess(0x1000, false, entry.ProcessID)
			if e != nil {
				return errors.New("a possible protected process is running but cannot be inspected; quit selected applications before installation")
			}
			var path [32768]uint16
			length := uint32(len(path))
			ok, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW").Call(uintptr(process), 0, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&length)))
			syscall.CloseHandle(process)
			if ok == 0 || length == 0 || length >= uint32(len(path)) {
				return errors.New("a possible protected process could not be identified; quit selected applications before installation")
			}
			actual, e := appBlob(syscall.UTF16ToString(path[:length]))
			if e != nil {
				return e
			}
			wanted, e := appBlob(program)
			if e != nil {
				wfpFree(unsafe.Pointer(actual))
				return e
			}
			matches := bytes.Equal(blobBytes(*actual), blobBytes(*wanted))
			wfpFree(unsafe.Pointer(actual))
			wfpFree(unsafe.Pointer(wanted))
			if matches {
				return errors.New("quit all selected applications and their helpers before installing persistent WFP restrictions")
			}
		}
		err = syscall.Process32Next(snapshot, &entry)
	}
	if err != syscall.ERROR_NO_MORE_FILES {
		return fmt.Errorf("cannot finish native process snapshot: %w", err)
	}
	return nil
}

// Enumerate actual BFE objects; never use a disk receipt to decide what exists.
// Product sublayer, providerless ownership, metadata and derived stable GUID
// must all match before deletion. Foreign associations are never removed.
func ownedFilterKeys(ctx context.Context, handle uintptr) ([]wfpGUID, error) {
	var enumerator uintptr
	if _, err := wfpCall("FwpmFilterCreateEnumHandle0", handle, 0, uintptr(unsafe.Pointer(&enumerator))); err != nil {
		return nil, err
	}
	defer wfpCall("FwpmFilterDestroyEnumHandle0", handle, enumerator)
	var keys []wfpGUID
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var entries **wfpFilter
		var count uint32
		_, err := wfpCall("FwpmFilterEnum0", handle, enumerator, 128, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count)))
		if err != nil {
			return nil, err
		}
		if count > 128 || (count > 0 && entries == nil) {
			wfpFree(unsafe.Pointer(entries))
			return nil, errors.New("invalid WFP enumeration")
		}
		for _, filter := range unsafe.Slice(entries, int(count)) {
			if filter != nil && filter.Sublayer == wfpSublayerKey {
				if filter.Provider != nil || !metadataOwnsRule(blobBytes(filter.Data), keyFromGUID(filter.Key)) {
					wfpFree(unsafe.Pointer(entries))
					return nil, errors.New("unrecognized object or provider association under ExitGuard sublayer")
				}
				keys = append(keys, filter.Key)
			}
		}
		wfpFree(unsafe.Pointer(entries))
		if count < 128 {
			break
		}
	}
	return keys, nil
}

func matchingNativeRuleSet(keys []wfpGUID, rules []denyRule) bool {
	if len(keys) != len(rules) {
		return false
	}
	want := make(map[wfpGUID]bool, len(rules))
	for _, rule := range rules {
		want[guidFromKey(rule.Key)] = true
	}
	for _, key := range keys {
		if !want[key] {
			return false
		}
		delete(want, key)
	}
	return len(want) == 0
}

func deleteOwnedFilters(ctx context.Context, handle uintptr) error {
	keys, err := ownedFilterKeys(ctx, handle)
	if err != nil {
		return err
	}
	for i := range keys {
		if _, err := wfpCall("FwpmFilterDeleteByKey0", handle, uintptr(unsafe.Pointer(&keys[i]))); err != nil {
			return err
		}
	}
	return nil
}
func remove(ctx context.Context, p Policy) error {
	handle, err := wfpOpen()
	if err != nil {
		return err
	}
	defer wfpCall("FwpmEngineClose0", handle)
	if _, err = wfpCall("FwpmTransactionBegin0", handle, 0); err != nil {
		return err
	}
	defer wfpCall("FwpmTransactionAbort0", handle)
	// A missing product sublayer means there are no product rules to remove.
	var sublayer *wfpSublayer
	code, err := wfpCall("FwpmSubLayerGetByKey0", handle, uintptr(unsafe.Pointer(&wfpSublayerKey)), uintptr(unsafe.Pointer(&sublayer)))
	if code == wfpNotFound || code == wfpSublayerNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	wfpFree(unsafe.Pointer(sublayer))
	if err = verifySublayer(handle); err != nil {
		return err
	}
	if err = deleteOwnedFilters(ctx, handle); err != nil {
		return err
	}
	if _, err = wfpCall("FwpmSubLayerDeleteByKey0", handle, uintptr(unsafe.Pointer(&wfpSublayerKey))); err != nil {
		return err
	}
	_, err = wfpCall("FwpmTransactionCommit0", handle)
	return err
}
