//go:build darwin

package guard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	"exitguard/internal/model"
)

type boundRoute struct {
	name        string
	fingerprint string
	index       int
	resolver    string
	bootstrap   string
}

func interfaceFingerprint(name string) (string, int, error) {
	if !strings.HasPrefix(name, "utun") || len(name) <= 4 {
		return "", 0, errors.New("请明确选择已确认属于飞连的 utun 接口")
	}
	for _, c := range name[4:] {
		if c < '0' || c > '9' {
			return "", 0, errors.New("隧道接口名称无效")
		}
	}
	i, e := net.InterfaceByName(name)
	if e != nil || i.Index <= 0 || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagPointToPoint == 0 {
		return "", 0, errors.New("已确认的飞连隧道接口不可用")
	}
	addrs, e := i.Addrs()
	if e != nil || len(addrs) == 0 {
		return "", 0, errors.New("隧道接口地址不可用")
	}
	names := make([]string, 0, len(addrs))
	for _, a := range addrs {
		names = append(names, a.String())
	}
	sort.Strings(names)
	return fmt.Sprintf("%s|%d|%d|%d|%s|%s", i.Name, i.Index, i.MTU, i.Flags, i.HardwareAddr, strings.Join(names, ",")), i.Index, nil
}
func newBoundRoute(c model.Config) (route, error) {
	if c.DNSResolverURL == "" || c.DNSBootstrapIP == "" {
		return nil, errors.New("飞连路径需要安全 DNS 与引导 IP")
	}
	fp, index, e := interfaceFingerprint(c.TunnelInterface)
	if e != nil {
		return nil, e
	}
	return &boundRoute{name: c.TunnelInterface, fingerprint: fp, index: index, resolver: c.DNSResolverURL, bootstrap: c.DNSBootstrapIP}, nil
}
func (r *boundRoute) Fingerprint(context.Context) (string, error) {
	fp, index, e := interfaceFingerprint(r.name)
	if e != nil || index != r.index || fp != r.fingerprint {
		return "", errors.New("隧道接口身份或地址已变化")
	}
	return fp, nil
}
func (r *boundRoute) Close() error { return nil }
func (r *boundRoute) Probe(ctx context.Context, raw string) (string, error) {
	return probeIP(ctx, r, raw)
}
func (r *boundRoute) dialLiteral(ctx context.Context, network, address string) (net.Conn, error) {
	if _, e := r.Fingerprint(ctx); e != nil {
		return nil, e
	}
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errors.New("绑定连接地址无效")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || !ip.Is4() {
		return nil, errors.New("仅允许 IPv4 字面量，禁止系统解析和未验证的 IPv6")
	}
	family := "tcp4"
	if ip.Is6() {
		family = "tcp6"
	}
	d := net.Dialer{Timeout: 7 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		var bindError error
		e := raw.Control(func(fd uintptr) { bindError = bindInterface(int(fd), family, r.index) })
		if e != nil {
			return fmt.Errorf("%w: raw socket", errInterfaceBinding)
		}
		return bindError
	}}
	tcpDone := beginProbeStage(ctx, diagnosticTargetTCP)
	c, e := d.DialContext(ctx, family, address)
	tcpDone(e)
	if e != nil {
		return nil, e
	}
	if _, e = r.Fingerprint(ctx); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func (r *boundRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("飞连路径仅支持 TCP")
	}
	host, port, e := targetAddress(address)
	if e != nil {
		return nil, e
	}
	if _, e := r.Fingerprint(ctx); e != nil {
		return nil, e
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return r.dialLiteral(ctx, network, address)
	}
	ips, e := resolveHTTPS(ctx, host, r.resolver, r.bootstrap, r.dialLiteral)
	if e != nil {
		return nil, e
	}
	for _, ip := range ips {
		if network == "tcp4" && strings.Contains(ip, ":") || network == "tcp6" && !strings.Contains(ip, ":") {
			continue
		}
		c, e := r.dialLiteral(ctx, network, net.JoinHostPort(ip, port))
		if e == nil {
			return c, nil
		}
		if errors.Is(e, errInterfaceBinding) {
			return nil, e
		}
		if _, changed := r.Fingerprint(ctx); changed != nil {
			return nil, changed
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("指定隧道内无法连接目标，无其他出口回退")
}

var errInterfaceBinding = errors.New("无法把网络套接字绑定到已确认的隧道接口")

func bindInterface(fd int, family string, index int) error {
	if index <= 0 {
		return errInterfaceBinding
	}
	var e error
	switch family {
	case "tcp4":
		e = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 25, index)
	case "tcp6":
		e = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, 125, index)
	default:
		return errInterfaceBinding
	}
	if e != nil {
		return errInterfaceBinding
	}
	return nil
}
