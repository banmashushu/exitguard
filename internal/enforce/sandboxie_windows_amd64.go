//go:build windows && amd64

package enforce

import (
	"context"
	"errors"
	"unsafe"
)

// FWPM_CALLOUT0, Windows SDK x64 ABI. Query flags include REGISTERED (0x40000).
// Sources: fwpmtypes.h; Sandboxie v1.18.8 core/drv/wfp.c WFP_RegisterCallout.
type sbieCallout struct {
	Key      wfpGUID
	Display  wfpDisplay
	Flags    uint32
	_        uint32
	Provider *wfpGUID
	Data     wfpBlob
	Layer    wfpGUID
	ID       uint32
	_        uint32
}

var _ [88 - unsafe.Sizeof(sbieCallout{})]byte
var _ [unsafe.Sizeof(sbieCallout{}) - 88]byte
var sbieSublayer = wfpGUID{0xe1d364e9, 0xcd84, 0x4a48, [8]byte{0xab, 0xa4, 0x60, 0x8c, 0xe8, 0x3e, 0x31, 0xee}}

func inspectSandboxie(ctx context.Context) ([]SandboxieFilter, error) {
	handle, err := wfpOpen()
	if err != nil {
		return nil, err
	}
	defer wfpCall("FwpmEngineClose0", handle)
	if _, err = wfpCall("FwpmTransactionBegin0", handle, 1); err != nil {
		return nil, err
	}
	defer wfpCall("FwpmTransactionAbort0", handle)
	layers := []wfpGUID{wfpConnect4, wfpConnect6, wfpAccept4, wfpAccept6}
	names := []string{"connect4", "connect6", "accept4", "accept6"}
	suffix := []byte{0xf6, 0xf7, 0xf8, 0xf9}
	var keys []wfpGUID
	var observations []SandboxieFilter
	for i, layer := range layers {
		d := [8]byte{0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, suffix[i]}
		if i == 1 || i == 3 {
			d[6] = 0xb9
		}
		key := wfpGUID{0x0bf56435, 0x71e4, 0x4de7, d}
		keys = append(keys, key)
		var callout *sbieCallout
		_, err := wfpCall("FwpmCalloutGetByKey0", handle, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&callout)))
		if err != nil {
			return observations, err
		}
		valid := callout != nil && callout.Key == key && callout.Layer == layer && callout.Flags == 0x40000 && callout.Provider == nil && callout.Data.Size == 0 && callout.ID != 0
		wfpFree(unsafe.Pointer(callout))
		observations = append(observations, SandboxieFilter{Layer: names[i], Registered: valid})
	}
	var enumerator uintptr
	if _, err = wfpCall("FwpmFilterCreateEnumHandle0", handle, 0, uintptr(unsafe.Pointer(&enumerator))); err != nil {
		return observations, err
	}
	defer wfpCall("FwpmFilterDestroyEnumHandle0", handle, enumerator)
	counts := [4]int{}
	for {
		if err := ctx.Err(); err != nil {
			return observations, err
		}
		var entries **wfpFilter
		var count uint32
		if _, err = wfpCall("FwpmFilterEnum0", handle, enumerator, 128, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count))); err != nil {
			return observations, err
		}
		if count > 128 || (count > 0 && entries == nil) {
			wfpFree(unsafe.Pointer(entries))
			return observations, errors.New("WFP 枚举结果无效")
		}
		valid := true
		for _, f := range unsafe.Slice(entries, int(count)) {
			if f == nil {
				valid = false
				continue
			}
			if f.Sublayer != sbieSublayer {
				continue
			}
			matched := false
			for i, key := range keys {
				if f.Action.Key == key && f.Layer == layers[i] {
					counts[i]++
					matched = true
					observations[i].Exact = f.Flags == 0 && f.Provider == nil && f.Data.Size == 0 && f.Count == 0 && f.Action.Type == 0x5003 && f.Weight.Type == 1 && f.Weight.Value == 15
				}
			}
			if !matched {
				valid = false
			}
		}
		wfpFree(unsafe.Pointer(entries))
		if !valid {
			return observations, errors.New("Sandboxie 子层存在未经审核的额外 WFP 规则")
		}
		if count < 128 {
			break
		}
	}
	for i, count := range counts {
		observations[i].Exact = observations[i].Exact && count == 1
	}
	return observations, validateSandboxieRuntime(observations)
}
