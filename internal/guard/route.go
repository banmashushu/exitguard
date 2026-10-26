package guard

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"exitguard/internal/model"
)

func newRoute(c model.Config, secret string) (route, error) {
	if c.Mode == "feilian" {
		return newBoundRoute(c)
	}
	if c.Mode == "proxy" {
		u, e := localHTTP(c.ProxyURL)
		if e != nil {
			return nil, e
		}
		port, _ := strconv.Atoi(u.Port())
		if port == int(c.ProxyPort) {
			return nil, errors.New("本地代理不能指向守护自身监听端口")
		}
		r, e := newUpstreamRoute(c.ProxyURL)
		if e != nil {
			return nil, e
		}
		r.resolver = c.DNSResolverURL
		r.bootstrap = c.DNSBootstrapIP
		return r, nil
	}
	if _, e := verifyClash(context.Background(), c, secret); e != nil {
		return nil, e
	}
	return nil, errors.New("当前 Clash 入口缺少可核验的专用监听绑定，不支持启用保护")
}
func targetAddress(address string) (string, string, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || host == "" || strings.ContainsAny(host, "\x00\r\n /\\@%") || len(host) > 253 {
		return "", "", errors.New("目标地址无效")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return "", "", errors.New("目标端口无效")
	}
	if ip, e := netip.ParseAddr(host); e == nil && !ip.Is4() {
		return "", "", errors.New("当前版本拒绝未经验证的 IPv6 目标")
	}
	if ip, e := netip.ParseAddr(host); e == nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Is4In6()) {
		return "", "", errors.New("不支持此目标地址")
	}
	return host, port, nil
}

type upstreamRoute struct {
	address    string
	scheme     string
	serverName string
	username   string
	password   string
	roots      *x509.CertPool
	ctx        context.Context
	cancel     context.CancelFunc
	resolver   string
	bootstrap  string
}

func newUpstreamRoute(raw string) (*upstreamRoute, error) {
	u, e := localHTTP(raw)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &upstreamRoute{address: u.Host, scheme: "http", resolver: "https://cloudflare-dns.com/dns-query", bootstrap: "1.1.1.1", ctx: ctx, cancel: cancel}, nil
}
func (r *upstreamRoute) Close() error { r.cancel(); return nil }
func (r *upstreamRoute) Fingerprint(ctx context.Context) (string, error) {
	if ctx.Err() != nil || r.ctx.Err() != nil {
		return "", errors.New("代理会话已关闭")
	}
	return r.scheme + "-upstream:" + r.serverName + ":" + r.address, nil
}
func (r *upstreamRoute) transportRoots() *x509.CertPool { return r.roots }
func (r *upstreamRoute) Probe(ctx context.Context, raw string) (string, error) {
	return probeIP(ctx, r, raw)
}
func (r *upstreamRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("当前版本仅支持 IPv4 TCP")
	}
	host, port, e := targetAddress(address)
	if e != nil {
		return nil, e
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return r.connect(ctx, network, address)
	}
	ips, e := resolveHTTPSWithRoots(ctx, host, r.resolver, r.bootstrap, r.connect, r.roots)
	if e != nil {
		return nil, e
	}
	for _, ip := range ips {
		c, e := r.connect(ctx, "tcp4", net.JoinHostPort(ip, port))
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("指定代理出口无法连接目标，无其他出口回退")
}
func (r *upstreamRoute) connect(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("仅支持 TCP")
	}
	if _, _, e := targetAddress(address); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopSession := context.AfterFunc(r.ctx, cancel)
	defer stopSession()
	if r.ctx.Err() != nil {
		return nil, errors.New("代理会话已关闭")
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	c, e := d.DialContext(ctx, "tcp", r.address)
	if e != nil {
		return nil, errors.New("指定代理上游不可达")
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	rawConn := c
	stop := context.AfterFunc(ctx, func() { rawConn.Close() })
	defer stop()
	deadline := time.Now().Add(8 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if r.scheme == "https" {
		secure := tls.Client(c, &tls.Config{ServerName: r.serverName, RootCAs: r.roots, MinVersion: tls.VersionTLS12})
		if e = secure.HandshakeContext(ctx); e != nil {
			return nil, errors.New("HTTPS 代理证书或 TLS 握手验证失败")
		}
		c = secure
	}
	stopRoute := context.AfterFunc(r.ctx, func() { c.Close() })
	defer func() {
		if !ok {
			stopRoute()
		}
	}()
	var reader *bufio.Reader
	if r.scheme == "socks5" {
		if e = r.socksConnect(c, address); e != nil {
			return nil, e
		}
	} else {
		var auth string
		if r.username != "" {
			auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(r.username+":"+r.password)) + "\r\n"
		}
		if _, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", address, address, auth); e != nil {
			return nil, errors.New("上游代理握手失败")
		}
		b := bufio.NewReaderSize(c, 4096)
		var header strings.Builder
		for {
			line, e := b.ReadSlice('\n')
			if e != nil || header.Len()+len(line) > 32<<10 {
				return nil, errors.New("上游响应头无效或过大")
			}
			header.Write(line)
			if string(line) == "\r\n" {
				break
			}
		}
		resp, e := http.ReadResponse(bufio.NewReader(strings.NewReader(header.String())), &http.Request{Method: "CONNECT"})
		if e != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errors.New("上游代理拒绝连接")
		}
		reader = b
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	owned := &routeConn{Conn: c, stop: stopRoute}
	if reader != nil {
		return &bufferedConn{Conn: owned, reader: reader}, nil
	}
	return owned, nil
}

type routeConn struct {
	net.Conn
	once sync.Once
	stop func() bool
}

func (c *routeConn) Close() error { c.once.Do(func() { c.stop() }); return c.Conn.Close() }

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func routeClient(r interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}) *http.Client {
	var roots *x509.CertPool
	if trusted, ok := r.(interface{ transportRoots() *x509.CertPool }); ok {
		roots = trusted.transportRoots()
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("不允许出口探测重定向") }, Transport: &http.Transport{Proxy: nil, DialContext: r.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10}}
}
func safeRequestURL(raw string) (*url.URL, error) {
	if e := secureURL(raw); e != nil {
		return nil, e
	}
	u, _ := url.Parse(raw)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if _, _, e := targetAddress(net.JoinHostPort(u.Hostname(), port)); e != nil {
		return nil, e
	}
	return u, nil
}
func readBounded(r io.Reader, n int64) ([]byte, error) {
	data, e := io.ReadAll(io.LimitReader(r, n+1))
	if e != nil || int64(len(data)) > n {
		return nil, errors.New("响应过大或读取失败")
	}
	return data, nil
}

// readResponseHead bounds headers without bounding or pre-consuming the tunnel/body.
func readResponseHead(reader *bufio.Reader, request *http.Request, max int) (*http.Response, error) {
	var header strings.Builder
	for {
		line, e := reader.ReadSlice('\n')
		if e != nil || header.Len()+len(line) > max {
			return nil, errors.New("响应头无效或过大")
		}
		header.Write(line)
		if string(line) == "\r\n" {
			break
		}
	}
	return http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader(header.String()), reader)), request)
}
