package guard

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"exitguard/internal/model"
)

// Dependencies are private and permit trusted local certificate fixtures without
// adding a user-facing TLS bypass or changing the machine's certificate store.
type remoteDependencies struct {
	lookupIP func(context.Context, string, string) ([]net.IP, error)
	roots    *x509.CertPool
}

func newRemoteRoute(ctx context.Context, c model.Config, username, password string) (route, error) {
	return newRemoteRouteWithDependencies(ctx, c, username, password, remoteDependencies{})
}
func newRemoteRouteWithDependencies(ctx context.Context, c model.Config, username, password string, deps remoteDependencies) (route, error) {
	if e := validateProxyCredentials(username, password); e != nil {
		return nil, e
	}
	u, e := remoteProxyURL(c.ProxyURL)
	if e != nil {
		return nil, e
	}
	host := u.Hostname()
	ip, e := netip.ParseAddr(host)
	if e != nil {
		lookup := deps.lookupIP
		if lookup == nil {
			lookup = net.DefaultResolver.LookupIP
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		// Only the proxy server itself is resolved with system DNS. All target
		// names use the configured DoH service through this pinned upstream.
		ips, err := lookup(lookupCtx, "ip4", host)
		if err != nil {
			return nil, errors.New("无法解析远程代理服务器的 IPv4 地址")
		}
		for _, candidate := range ips {
			v, ok := netip.AddrFromSlice(candidate)
			if ok && v.Unmap().Is4() {
				ip = v.Unmap()
				break
			}
		}
	}
	if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("远程代理未提供可用 IPv4 地址")
	}
	port, _ := strconv.Atoi(u.Port())
	if ip.IsLoopback() && port == int(c.ProxyPort) {
		return nil, errors.New("远程代理不能指向守护自身监听端口")
	}
	if ctx.Err() != nil {
		return nil, errors.New("远程代理初始化已取消")
	}
	session, cancel := context.WithCancel(context.Background())
	return &upstreamRoute{address: net.JoinHostPort(ip.String(), u.Port()), scheme: u.Scheme, serverName: host, username: username, password: password, roots: deps.roots, resolver: c.DNSResolverURL, bootstrap: c.DNSBootstrapIP, ctx: session, cancel: cancel}, nil
}

func (r *upstreamRoute) socksConnect(c net.Conn, address string) error {
	fail := &upstreamError{"SOCKS5 代理握手或认证失败"}
	method := byte(0)
	if r.username != "" {
		method = 2
	}
	if _, e := c.Write([]byte{5, 1, method}); e != nil {
		return transportFailure(stageSOCKSHandshake, e, false)
	}
	var response [2]byte
	if e := readSOCKSFrame(c, response[:]); e != nil {
		return e
	}
	if response[0] != 5 || response[1] != method {
		return fail
	}
	if method == 2 {
		auth := []byte{1, byte(len(r.username))}
		auth = append(auth, r.username...)
		auth = append(auth, byte(len(r.password)))
		auth = append(auth, r.password...)
		if _, e := c.Write(auth); e != nil {
			return transportFailure(stageSOCKSHandshake, e, false)
		}
		if e := readSOCKSFrame(c, response[:]); e != nil {
			return e
		}
		if response[0] != 1 || response[1] != 0 {
			return fail
		}
	}
	host, port, e := targetAddress(address)
	if e != nil {
		return fail
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || !ip.Is4() {
		return errors.New("SOCKS5 目标须先经指定出口解析为 IPv4")
	}
	n, _ := strconv.Atoi(port)
	request := []byte{5, 1, 0, 1}
	a := ip.As4()
	request = append(request, a[:]...)
	request = binary.BigEndian.AppendUint16(request, uint16(n))
	if _, e = c.Write(request); e != nil {
		return transportFailure(stageSOCKSHandshake, e, false)
	}
	var head [4]byte
	if e := readSOCKSFrame(c, head[:]); e != nil {
		return e
	}
	if head[0] != 5 || head[2] != 0 {
		return fail
	}
	var size int
	switch head[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, e = io.ReadFull(c, length[:]); e != nil || length[0] == 0 {
			return fail
		}
		size = int(length[0])
	default:
		return fail
	}
	if _, e = io.CopyN(io.Discard, c, int64(size+2)); e != nil {
		return fail
	}
	// Consume and validate the entire reply before interpreting a negative REP.
	// General/server/protocol failures remain global; REP 2..6 describe this
	// CONNECT destination after the upstream authenticated successfully.
	switch head[1] {
	case 0:
		return nil
	case 2:
		return &destinationError{"SOCKS5 代理规则拒绝此目标"}
	case 3:
		return &destinationError{"SOCKS5 目标网络不可达"}
	case 4:
		return &destinationError{"SOCKS5 目标主机不可达"}
	case 5:
		return &destinationError{"SOCKS5 目标连接被拒绝"}
	case 6:
		return &destinationError{"SOCKS5 目标连接 TTL 已过期"}
	default:
		return &upstreamError{"SOCKS5 代理返回一般故障或不支持的连接响应"}
	}
}

func readSOCKSFrame(c io.Reader, frame []byte) error {
	n, err := io.ReadFull(c, frame)
	if err == nil {
		return nil
	}
	if n == 0 {
		return transportFailure(stageSOCKSHandshake, err, false)
	}
	// A partial protocol frame is not a validated response or a mere idle close.
	return &upstreamError{"SOCKS5 代理握手或认证失败"}
}
