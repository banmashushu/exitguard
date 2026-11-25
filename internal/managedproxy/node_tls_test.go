package managedproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"exitguard/internal/subscription"
)

// This fixture only accepts the exact synthetic Trojan password and one local
// destination. It cannot reach a subscription server or a public endpoint.
func TestOfficialCoreHonorsTrojanCertificateSetting(t *testing.T) {
	b := officialBundle(t)
	const password = "trojan-fixture-password"
	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		fmt.Fprint(w, "node-tls-fixture")
	}))
	t.Cleanup(origin.Close)
	target := strings.TrimPrefix(origin.URL, "http://")
	_, targetPort, _ := net.SplitHostPort(target)
	wantPort, _ := strconv.Atoi(targetPort)
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				reader := bufio.NewReader(conn)
				var header [68]byte
				if _, err := io.ReadFull(reader, header[:]); err != nil {
					return // The default-verification case must fail its TLS handshake.
				}
				digest := sha256.Sum224([]byte(password))
				if string(header[:56]) != hex.EncodeToString(digest[:]) || string(header[56:58]) != "\r\n" || header[58] != 1 || header[59] != 1 || !net.IP(header[60:64]).Equal(net.IPv4(127, 0, 0, 1)) || int(header[64])<<8|int(header[65]) != wantPort || string(header[66:]) != "\r\n" {
					t.Error("core changed Trojan authentication or the fixture destination")
					return
				}
				out, err := net.DialTimeout("tcp4", target, time.Second)
				if err != nil {
					return
				}
				defer out.Close()
				go func() { _, _ = io.Copy(out, reader) }()
				_, _ = io.Copy(conn, out)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-acceptDone; workers.Wait() })
	_, rawPort, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	for _, skip := range []bool{true, false} {
		t.Run(fmt.Sprintf("skip=%t", skip), func(t *testing.T) {
			config := map[string]any{"type": "trojan", "server": "selected-node.invalid", "port": port, "password": password, "udp": false, "tls": true, "network": "tcp", "sni": "explicit-authority.invalid"}
			if skip {
				config["skip-cert-verify"] = true
			}
			node := Node{Identity: subscription.Identity(config), Config: config}
			manager := localFixtureManager(t, b)
			lease, err := manager.Ensure(context.Background(), node)
			if err != nil {
				t.Fatal("requested node setting was rejected before core startup", err)
			}
			conn, err := net.Dial("tcp4", strings.TrimPrefix(lease.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			before := originHits.Load()
			reader := connectThrough(t, conn, target, lease.Username, lease.Password)
			fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n")
			response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
			if !skip {
				if err == nil || originHits.Load() != before {
					t.Fatal("a different node inherited disabled certificate verification")
				}
				return
			}
			if err != nil {
				t.Fatal("explicit node setting did not permit the self-signed fixture", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 128))
			if err != nil || response.StatusCode != 200 || string(body) != "node-tls-fixture" || originHits.Load() != before+1 {
				t.Fatal("selected node did not carry the controlled HTTPS-protected tunnel")
			}
		})
	}
}
