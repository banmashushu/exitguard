package nativeprobe

import (
	"net"
	"testing"
	"time"
)

func TestTCPObservationReportsRealReachabilityWithoutProtectionClaim(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	reached := TCP(address, 200*time.Millisecond)
	if !reached.Connected || reached.Error != "" {
		t.Fatal("lost positive control", reached)
	}
	listener.Close()
	closed := TCP(address, 200*time.Millisecond)
	if closed.Connected || closed.Error == "" {
		t.Fatal("a refused port must stay a raw failure, never a proof of firewall blocking", closed)
	}
}
