package subscription

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrDownload = errors.New("订阅 HTTPS 下载失败或地址不符合要求")
var ErrActiveRouteUnavailable = errors.New("当前没有可用于下载订阅的已验证活动出口；请先检查并启动固定出口后重试")

type DialContext func(context.Context, string, string) (net.Conn, error)

type downloadDependencies struct {
	lookup func(context.Context, string, string) ([]net.IP, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  *x509.CertPool
}

func validateDownloadURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 8192 {
		return ErrDownload
	}
	return nil
}
func Fetch(ctx context.Context, raw string) ([]byte, error) {
	return fetchWithDependencies(ctx, raw, downloadDependencies{})
}

// FetchThrough uses only the explicitly supplied route. It never substitutes a
// direct dial, including after a redirect or an inactive-route error.
func FetchThrough(ctx context.Context, raw string, dial DialContext) ([]byte, error) {
	return fetchThroughWithDependencies(ctx, raw, dial, downloadDependencies{})
}
func fetchThroughWithDependencies(ctx context.Context, raw string, dial DialContext, deps downloadDependencies) ([]byte, error) {
	if dial == nil {
		return nil, ErrActiveRouteUnavailable
	}
	deps.dial = dial
	return fetchWithDependencies(ctx, raw, deps)
}
func fetchWithDependencies(ctx context.Context, raw string, deps downloadDependencies) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for redirects := 0; redirects <= 2; redirects++ {
		if validateDownloadURL(raw) != nil {
			return nil, ErrDownload
		}
		u, _ := url.Parse(raw)
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		var pinned string
		if ip, e := netip.ParseAddr(host); e == nil {
			if !PublicIPv4(ip) {
				return nil, ErrDownload
			}
			pinned = ip.String()
		} else {
			lookup := deps.lookup
			if lookup == nil {
				lookup = net.DefaultResolver.LookupIP
			}
			ips, e := lookup(ctx, "ip4", host)
			if e != nil || len(ips) == 0 {
				return nil, ErrDownload
			}
			for _, candidate := range ips {
				ip, ok := netip.AddrFromSlice(candidate)
				if !ok || !PublicIPv4(ip.Unmap()) {
					return nil, ErrDownload
				}
				if pinned == "" {
					pinned = ip.Unmap().String()
				}
			}
		}
		dial := deps.dial
		if dial == nil {
			dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
		}
		transport := &http.Transport{Proxy: nil, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
			if !strings.EqualFold(address, net.JoinHostPort(host, port)) {
				return nil, ErrDownload
			}
			return dial(c, "tcp4", net.JoinHostPort(pinned, port))
		}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: deps.roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if e != nil {
			return nil, ErrDownload
		}
		req.Header.Set("User-Agent", "ExitGuard/0.2.2")
		resp, e := client.Do(req)
		if e != nil {
			transport.CloseIdleConnections()
			if errors.Is(e, ErrActiveRouteUnavailable) {
				return nil, ErrActiveRouteUnavailable
			}
			return nil, ErrDownload
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			next, e := resp.Location()
			resp.Body.Close()
			transport.CloseIdleConnections()
			if e != nil {
				return nil, ErrDownload
			}
			raw = next.String()
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			transport.CloseIdleConnections()
			return nil, ErrDownload
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
		resp.Body.Close()
		transport.CloseIdleConnections()
		if e != nil || len(b) > MaxBytes {
			return nil, ErrDownload
		}
		if failure := sourceResponseFailure(b); failure != nil {
			return nil, failure
		}
		return b, nil
	}
	return nil, ErrDownload
}

// PublicIPv4 excludes private, shared, benchmark, documentation and reserved ranges.
func PublicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}
