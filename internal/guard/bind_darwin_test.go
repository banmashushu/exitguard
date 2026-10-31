//go:build darwin

package guard

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestSocketBindingRejectsMissingInterfaceAndFamily(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		af := syscall.AF_INET
		if family == "tcp6" {
			af = syscall.AF_INET6
		}
		fd, e := syscall.Socket(af, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		if e != nil {
			t.Fatal(e)
		}
		for _, index := range []int{0, -1, 2147483647} {
			if e := bindInterface(fd, family, index); !errors.Is(e, errInterfaceBinding) {
				t.Fatalf("%s index %d binding did not fail closed: %v", family, index, e)
			}
		}
		syscall.Close(fd)
	}
}
func TestPhysicalInterfaceCannotBeUsedAsFeilianTunnel(t *testing.T) {
	if _, _, e := interfaceFingerprint("lo0"); e == nil {
		t.Fatal("physical/loopback interface accepted as VPN")
	}
	r := &boundRoute{name: "utun-no-such-exitguard", index: 2147483647}
	if c, e := r.dialLiteral(context.Background(), "tcp", "203.0.113.7:443"); e == nil {
		c.Close()
		t.Fatal("missing interface connected")
	}
}
