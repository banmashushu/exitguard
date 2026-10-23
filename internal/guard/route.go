package guard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"exitguard/internal/model"
)

func newRoute(c model.Config, secret string) (route, error) {
	if c.Mode == "feilian" {
		return newBoundRoute(c)
	}
	if c.Mode == "proxy" {
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
	address   string
	resolver  string
	bootstrap string
}

func newUpstreamRoute(raw string) (*upstreamRoute, error) {
	u, e := localHTTP(raw)
	if e != nil {
		return nil, e
	}
	return &upstreamRoute{address: u.Host, resolver: "https://cloudflare-dns.com/dns-query", bootstrap: "1.1.1.1"}, nil
}
func (r *upstreamRoute) Close() error { return nil }
func (r *upstreamRoute) Fingerprint(context.Context) (string, error) {
	return "http-upstream:" + r.address, nil
}
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
	ips, e := resolveHTTPS(ctx, host, r.resolver, r.bootstrap, r.connect)
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
	return nil, errors.New("本地专用出口无法连接目标，无其他出口回退")
}
func (r *upstreamRoute) connect(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("仅支持 TCP")
	}
	if _, _, e := targetAddress(address); e != nil {
		return nil, e
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	c, e := d.DialContext(ctx, "tcp", r.address)
	if e != nil {
		return nil, errors.New("本地上游不可达")
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(8 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address); e != nil {
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
	if e != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("上游代理拒绝连接")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return &bufferedConn{Conn: c, reader: b}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func routeClient(r interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("不允许出口探测重定向") }, Transport: &http.Transport{Proxy: nil, DialContext: r.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10}}
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
