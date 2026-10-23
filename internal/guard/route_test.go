package guard

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpstreamCONNECTPreservesDestinationAndNeverDirects(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Host
		if r.Method != "CONNECT" {
			t.Errorf("method %s", r.Method)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	r, e := newUpstreamRoute(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	if c, e := r.connect(context.Background(), "tcp", "forbidden.invalid:443"); e == nil {
		c.Close()
		t.Fatal("upstream denial bypassed")
	}
	if got != "forbidden.invalid:443" {
		t.Fatalf("wrong CONNECT destination %q", got)
	}
}
func TestUpstreamConnectTunnelBytesAreUntouched(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		fmt.Fprint(b, "HTTP/1.1 200 Connection Established\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
	}))
	defer server.Close()
	r, e := newUpstreamRoute(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	c, e := r.connect(context.Background(), "tcp", "origin.example:443")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	payload := "opaque TLS bytes\x00"
	if _, e = io.WriteString(c, payload); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, len(payload))
	if _, e = io.ReadFull(c, data); e != nil {
		t.Fatal(e)
	}
	if string(data) != payload {
		t.Fatal("tunnel payload altered")
	}
}
func TestClashRejectsNestedDynamicAndDirectNodes(t *testing.T) {
	for _, kind := range []string{"Direct", "Reject", "Selector", "URLTest", "Fallback", "LoadBalance"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "ExitGuard") {
					fmt.Fprint(w, `{"type":"Selector","now":"Fixed","all":["Fixed"]}`)
				} else {
					fmt.Fprintf(w, `{"type":%q}`, kind)
				}
			}))
			defer server.Close()
			c := validConfig(t)
			c.ClashControllerURL = server.URL
			if _, e := verifyClash(context.Background(), c, ""); e == nil {
				t.Fatal("unsafe Clash leaf accepted")
			}
		})
	}
}
func TestClashOnlyReadsDedicatedSelection(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if strings.HasSuffix(r.URL.Path, "ExitGuard") {
			fmt.Fprint(w, `{"type":"Selector","now":"Fixed","all":["Fixed"]}`)
		} else {
			fmt.Fprint(w, `{"type":"Shadowsocks","udp":false}`)
		}
	}))
	defer server.Close()
	c := validConfig(t)
	c.ClashControllerURL = server.URL
	if fp, e := verifyClash(context.Background(), c, ""); e != nil || fp == "" {
		t.Fatalf("leaf verification %q %v", fp, e)
	}
	for _, m := range methods {
		if m != "GET" {
			t.Fatal("controller mutated")
		}
	}
}
func TestDNSWireRejectsTruncatedAndUnrelatedAnswers(t *testing.T) {
	query, e := dnsQuestion("example.com", 1)
	if e != nil {
		t.Fatal(e)
	}
	for _, answer := range [][]byte{nil, query, append([]byte(nil), query[:8]...)} {
		if _, e := dnsAnswers(answer, query, 1); e == nil {
			t.Fatal("accepted non-answer")
		}
	}
	answer := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	binary.BigEndian.PutUint16(answer[6:8], 1)
	answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7)
	ips, e := dnsAnswers(answer, query, 1)
	if e != nil || len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Fatalf("DNS answer %v %v", ips, e)
	}
	answer[0] ^= 1
	if _, e = dnsAnswers(answer, query, 1); e == nil {
		t.Fatal("accepted mismatched query ID")
	}
}
func TestCONNECTResponseWithLargeHeaderIsRejected(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		http.ReadRequest(bufio.NewReader(c))
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\nX-Oversize: "+strings.Repeat("a", 70<<10)+"\r\n\r\n")
	}()
	r, e := newUpstreamRoute("http://" + l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	if c, e := r.connect(context.Background(), "tcp", "origin.example:443"); e == nil {
		c.Close()
		t.Fatal("unbounded upstream response accepted")
	}
}

func TestClashNamesAreEscapedExactlyOnce(t *testing.T) {
	c := validConfig(t)
	c.ClashSelector = "Exit/Guard"
	c.ClashNode = "Fixed/Node"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxies/Exit/Guard":
			fmt.Fprint(w, `{"type":"Selector","now":"Fixed/Node","all":["Fixed/Node"]}`)
		case "/proxies/Fixed/Node":
			fmt.Fprint(w, `{"type":"Shadowsocks"}`)
		default:
			http.Error(w, "wrong escaped resource", 404)
		}
	}))
	defer server.Close()
	c.ClashControllerURL = server.URL
	if _, e := verifyClash(context.Background(), c, ""); e != nil {
		t.Fatalf("selector/node names double escaped: %v", e)
	}
}
func TestSecureDNSFailureNeverUsesSystemResolver(t *testing.T) {
	var endpoint string
	calls := 0
	_, e := resolveHTTPS(context.Background(), "unique-exitguard-test.invalid", "https://resolver.invalid/dns-query", "203.0.113.55", func(_ context.Context, network, address string) (net.Conn, error) {
		calls++
		endpoint = address
		return nil, fmt.Errorf("bound path unavailable")
	})
	if e == nil || calls != 1 || endpoint != "203.0.113.55:443" {
		t.Fatalf("unsafe DNS path: endpoint=%q calls=%d err=%v", endpoint, calls, e)
	}
}

func TestProtectedRouteRejectsIPv6BeforeConnecting(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer server.Close()
	r, e := newUpstreamRoute(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	if c, e := r.DialContext(context.Background(), "tcp", "[2001:db8::1]:443"); e == nil {
		c.Close()
		t.Fatal("unverified IPv6 target admitted")
	}
	if calls != 0 {
		t.Fatal("IPv6 rejection happened after outbound connection")
	}
}

func TestSecureDNSOnlyQueriesAAndReturnsRelatedIPv4(t *testing.T) {
	var types []uint16
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad DNS transport", 400)
			return
		}
		q, e := io.ReadAll(r.Body)
		if e != nil || len(q) < 12 {
			http.Error(w, "bad DNS question", 400)
			return
		}
		_, end, e := dnsName(q, 12)
		if e != nil {
			http.Error(w, "bad name", 400)
			return
		}
		types = append(types, binary.BigEndian.Uint16(q[end:end+2]))
		answer := append([]byte(nil), q...)
		binary.BigEndian.PutUint16(answer[2:4], 0x8180)
		binary.BigEndian.PutUint16(answer[6:8], 1)
		answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer)
	}))
	defer server.Close()
	ips, e := queryIPv4(context.Background(), "origin.example", server.URL, server.Client())
	if e != nil || len(ips) != 1 || ips[0] != "203.0.113.7" || len(types) != 1 || types[0] != 1 {
		t.Fatalf("unexpected family or DNS result %v %v %v", ips, types, e)
	}
}
func TestProxyDNSUsesSameUpstreamWithBootstrapLiteral(t *testing.T) {
	var destinations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinations = append(destinations, r.Host)
		w.WriteHeader(403)
	}))
	defer server.Close()
	r, e := newUpstreamRoute(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	if c, e := r.DialContext(context.Background(), "tcp", "origin.invalid:443"); e == nil {
		c.Close()
		t.Fatal("DNS failure should deny destination")
	}
	if len(destinations) != 1 || destinations[0] != "1.1.1.1:443" {
		t.Fatalf("DNS bypassed dedicated upstream %v", destinations)
	}
}
