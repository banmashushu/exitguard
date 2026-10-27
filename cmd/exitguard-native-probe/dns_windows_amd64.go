//go:build windows && amd64

package main

import (
	"syscall"
	"unsafe"
)

// DNS_QUERY_REQUEST / DNS_QUERY_RESULT x64 SDK layouts. Synchronous callback=nil.
// https://learn.microsoft.com/windows/win32/api/windns/ns-windns-dns_query_request
// DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE avoid a cache-only observation.
type dnsRequest struct {
	Version           uint32
	_                 uint32
	Name              *uint16
	Type              uint16
	_                 [6]byte
	Options           uint64
	Servers           uintptr
	Interface         uint32
	_                 uint32
	Callback, Context uintptr
}
type dnsResult struct {
	Version           uint32
	Status            int32
	Options           uint64
	Records, Reserved uintptr
}

var _ [64 - unsafe.Sizeof(dnsRequest{})]byte
var _ [unsafe.Sizeof(dnsRequest{}) - 64]byte
var _ [32 - unsafe.Sizeof(dnsResult{})]byte
var _ [unsafe.Sizeof(dnsResult{}) - 32]byte

func dnsObservations(name string) any {
	query, _ := syscall.UTF16PtrFromString(name)
	result := map[string]any{"query": name, "state": "incomplete", "notice": "返回码不是 DNS 无泄漏证明，需同时观察 DNS Client broker/物理接口/受控权威 DNS。"}
	var address *syscall.AddrinfoW
	code := syscall.GetAddrInfoW(query, nil, nil, &address)
	if code != nil {
		result["GetAddrInfoWError"] = code.Error()
	} else {
		result["GetAddrInfoWStatus"] = 0
	}
	if address != nil {
		syscall.FreeAddrInfoW(address)
	}
	// dnsapi is a Windows system library, never searched from the application dir.
	var system [32768]uint16
	n, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&system[0])), uintptr(len(system)))
	if n == 0 || n >= uintptr(len(system)) {
		result["DnsQueryExError"] = "system directory unavailable"
		return result
	}
	dll, err := syscall.LoadDLL(syscall.UTF16ToString(system[:n]) + `\dnsapi.dll`)
	if err != nil {
		result["DnsQueryExError"] = "Windows DNS API unavailable"
		return result
	}
	defer dll.Release()
	proc, err := dll.FindProc("DnsQueryEx")
	if err != nil {
		result["DnsQueryExError"] = "unsupported Windows DNS API"
		return result
	}
	request := dnsRequest{Version: 1, Name: query, Type: 1, Options: 8 | 64}
	answer := dnsResult{Version: 1}
	status, _, _ := proc.Call(uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&answer)), 0)
	result["DnsQueryExReturnCode"] = uint32(status)
	result["DnsQueryExQueryStatus"] = answer.Status
	if answer.Records != 0 {
		if free, err := dll.FindProc("DnsRecordListFree"); err == nil {
			free.Call(answer.Records, 1)
		}
	}
	return result
}
