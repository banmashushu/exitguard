package subscription

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloaderPinsEveryRedirectAndNeverLeaksSource(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://private.example/token-private")
			w.WriteHeader(302)
			return
		}
		fmt.Fprint(w, "proxies: []")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	var dials atomic.Int32
	deps := downloadDependencies{roots: roots, lookup: func(_ context.Context, _ string, host string) ([]net.IP, error) {
		if host == "private.example" {
			return []net.IP{net.ParseIP("100.64.1.1")}, nil
		}
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "8.8.8.8:"+u.Port() {
			t.Error("download was not pinned")
		}
		dials.Add(1)
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", u.Host)
	}}
	if b, e := fetchWithDependencies(context.Background(), "https://example.com:"+u.Port()+"/ok?private-token", deps); e != nil || string(b) != "proxies: []" {
		t.Fatal("pinned fixture failed", e)
	}
	before := dials.Load()
	if _, e := fetchWithDependencies(context.Background(), "https://example.com:"+u.Port()+"/redirect", deps); e == nil || strings.Contains(e.Error(), "private") {
		t.Fatal("redirect reached reserved network or leaked source")
	}
	if dials.Load() != before+1 {
		t.Fatal("redirect dialed reserved destination")
	}
	for _, address := range []string{"https://100.64.1.1/token-private", "https://198.18.0.1/token-private", "https://192.0.2.1/token-private", "http://example.com/private", "https://user:pass@example.com/private"} {
		before := dials.Load()
		if _, e := fetchWithDependencies(context.Background(), address, deps); e == nil {
			t.Fatal("unsafe source accepted")
		}
		if dials.Load() != before {
			t.Fatal("unsafe source dialed")
		}
	}
}

func TestDownloaderClassifiesEmptyAndKnownClientDenial(t *testing.T) {
	for _, test := range []struct{ name, body, want string }{{"empty", "", "空"}, {"whitespace", " \r\n\t", "空"}, {"denied", "This client is not allowed to fetch subscription\r\n", "客户端"}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, test.body) }))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			parsed, _ := url.Parse(server.URL)
			deps := downloadDependencies{roots: roots, lookup: func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }, dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp4", parsed.Host)
			}}
			content, e := fetchWithDependencies(context.Background(), "https://example.com:"+parsed.Port()+"/private-source", deps)
			if e == nil || len(content) != 0 || !strings.Contains(e.Error(), test.want) || strings.Contains(e.Error(), "private-source") {
				t.Fatal("successful error response lost safe actionable category")
			}
		})
	}
}

func TestFetchThroughRequiresExplicitDialAndNeverFallsBack(t *testing.T) {
	if _, e := FetchThrough(context.Background(), "https://8.8.8.8/private-source", nil); !errors.Is(e, ErrActiveRouteUnavailable) {
		t.Fatal("nil active dialer could use direct transport")
	}
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, e := FetchThrough(ctx, "https://8.8.8.8/private-source", func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, ErrActiveRouteUnavailable
	}); !errors.Is(e, ErrActiveRouteUnavailable) || calls != 1 {
		t.Fatal("active dial failure fell back or lost safe category")
	}
}

func TestExplicitDialRetainsRedirectPinningAndRejectsPrivateTargets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/next":
			w.Header().Set("Location", "/ok")
			w.WriteHeader(302)
		case "/private":
			w.Header().Set("Location", "https://private.example/blocked")
			w.WriteHeader(302)
		default:
			io.WriteString(w, "proxies: [{name: Fictitious, type: http, server: node.example, port: 443}]")
		}
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dials, lookups := 0, 0
	deps := downloadDependencies{roots: roots, lookup: func(_ context.Context, _ string, host string) ([]net.IP, error) {
		lookups++
		if host == "private.example" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}}
	routeDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials++
		if network != "tcp4" || address != "8.8.8.8:"+parsed.Port() {
			t.Error("redirect escaped pinned route dialer")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", parsed.Host)
	}
	body, e := fetchThroughWithDependencies(context.Background(), "https://example.com:"+parsed.Port()+"/next", routeDial, deps)
	if e != nil || len(body) == 0 || dials != 2 || lookups != 2 {
		t.Fatal("redirect did not retain explicit route and per-hop pinning", e)
	}
	before := dials
	if _, e = fetchThroughWithDependencies(context.Background(), "https://example.com:"+parsed.Port()+"/private", routeDial, deps); e == nil || dials != before+1 {
		t.Fatal("redirect used private target or another dialer")
	}
	before = dials
	if _, e = FetchThrough(context.Background(), "https://127.0.0.1/private-source", routeDial); e == nil || dials != before {
		t.Fatal("private literal reached route")
	}
}
