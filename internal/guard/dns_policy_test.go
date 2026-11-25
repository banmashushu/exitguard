package guard

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestCapturedQQLocalLoginDNSIsTargetRefusal(t *testing.T) {
	query, err := os.ReadFile("testdata/qq-local-login.query")
	if err != nil {
		t.Fatal(err)
	}
	response, err := os.ReadFile("testdata/qq-local-login.response")
	if err != nil {
		t.Fatal(err)
	}
	ips, err := dnsAnswers(response, query, 1)
	var refused *destinationError
	if len(ips) != 0 || !errors.As(err, &refused) {
		t.Fatalf("valid QQ loopback reply must refuse only this target: ips=%v err=%v", ips, err)
	}
}

func TestQQLocalLoginDoesNotDisconnectOtherProxyConnections(t *testing.T) {
	for _, method := range []string{"HTTP", "CONNECT"} {
		t.Run(method, func(t *testing.T) {
			f := newDestinationFixture(t)
			echo, echoed := f.echo(t)
			before := f.s.Status()
			if method == "HTTP" {
				response, err := f.client.Get("http://localhost.ptlogin2.qq.com:4301/")
				if err != nil {
					t.Fatalf("QQ local login killed the session: %v; status=%+v", err, f.s.Status())
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "目标") {
					t.Fatalf("local target was not explicitly refused: HTTP %d %q", response.StatusCode, body)
				}
			} else {
				response := proxyRaw(t, f.s, "CONNECT localhost.ptlogin2.qq.com:4301 HTTP/1.1\r\nHost: localhost.ptlogin2.qq.com:4301\r\n\r\n")
				if !strings.Contains(response, "502") {
					t.Fatalf("QQ CONNECT killed the session instead of returning502: %q; status=%+v", response, f.s.Status())
				}
			}
			if after := f.s.Status(); after.State != "proxy_active" || after.SessionRevision != before.SessionRevision {
				t.Fatalf("local login target revoked the session: %+v", after)
			}
			assertEchoSurvives(t, echo, echoed)
			if f.localTargetDials.Load() != 0 {
				t.Fatal("proxy attempted a connection to the rejected loopback target")
			}
			f.healthy(t)
		})
	}
}

func TestDNSPolicyRefusalRequiresCompleteConsistentAnswer(t *testing.T) {
	query, err := dnsQuestion("policy.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	aRecord := func(ip ...byte) []byte {
		return append([]byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, byte(len(ip))}, ip...)
	}
	for _, tc := range []struct {
		name    string
		records [][]byte
		rcode   uint16
		local   bool
	}{
		{"loopback", [][]byte{aRecord(127, 0, 0, 1)}, 0, true},
		{"unspecified", [][]byte{aRecord(0, 0, 0, 0)}, 0, true},
		{"link-local", [][]byte{aRecord(169, 254, 1, 2)}, 0, true},
		{"multicast", [][]byte{aRecord(224, 0, 0, 1)}, 0, true},
		{"mixed", [][]byte{aRecord(203, 0, 113, 7), aRecord(127, 0, 0, 1)}, 0, true},
		{"malformed-after-loopback", [][]byte{aRecord(127, 0, 0, 1), aRecord(1, 2, 3)}, 0, false},
		{"nxdomain-with-loopback", [][]byte{aRecord(127, 0, 0, 1)}, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := append([]byte(nil), query...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180|tc.rcode)
			binary.BigEndian.PutUint16(response[6:8], uint16(len(tc.records)))
			for _, record := range tc.records {
				response = append(response, record...)
			}
			ips, err := dnsAnswers(response, query, 1)
			var refused *destinationError
			if err == nil || len(ips) != 0 || errors.As(err, &refused) != tc.local {
				t.Fatalf("unsafe policy classification: ips=%v err=%v", ips, err)
			}
		})
	}
}

func TestDNSAliasedLoopbackWithAddressBeforeCNAME(t *testing.T) {
	query, err := dnsQuestion("policy.example", 1)
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 2)
	alias := []byte{5, 'a', 'l', 'i', 'a', 's', 0}
	response = append(response, alias...)
	response = append(response, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
	response = append(response, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, byte(len(alias)))
	response = append(response, alias...)
	ips, err := dnsAnswers(response, query, 1)
	var refused *destinationError
	if len(ips) != 0 || !errors.As(err, &refused) {
		t.Fatalf("aliased loopback was not isolated: ips=%v err=%v", ips, err)
	}
}
