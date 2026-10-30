package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"exitguard/internal/model"
)

func defaults(c model.Config) model.Config {
	// An explicit or saved legacy configuration must retain strict enforcement.
	if c.EnforcementMode == "" {
		c.EnforcementMode = "required"
	}
	if c.Mode == "" {
		if runtime.GOOS == "windows" {
			c.Mode = "clash"
		} else {
			c.Mode = "feilian"
		}
	}
	if c.ProxyPort == 0 {
		c.ProxyPort = 17890
	}
	if c.DNSResolverURL == "" {
		c.DNSResolverURL = "https://cloudflare-dns.com/dns-query"
	}
	if c.DNSBootstrapIP == "" {
		c.DNSBootstrapIP = "1.1.1.1"
	}
	if c.ProbeURL == "" {
		c.ProbeURL = "https://api.ipify.org?format=json"
	}
	return c
}
func copyConfig(c model.Config) model.Config {
	c.ExpectedIPs = append([]string(nil), c.ExpectedIPs...)
	c.Programs = append([]string(nil), c.Programs...)
	c.BundleIDs = append([]string(nil), c.BundleIDs...)
	return c
}
func localHTTP(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("本地代理和控制接口必须是无凭证、无参数的 HTTP 地址")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.IsLoopback() || ip.Is4In6() || u.Port() == "" {
		return nil, errors.New("本地地址必须使用明确的回环 IP 和端口")
	}
	if _, e = net.LookupPort("tcp", u.Port()); e != nil {
		return nil, errors.New("本地端口无效")
	}
	return u, nil
}
func secureURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("探测和 DNS 地址必须使用 HTTPS 且不包含凭证")
	}
	return nil
}
func remoteProxyURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") || u.User != nil || u.Hostname() == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("远程代理必须是无凭证、路径或参数的 HTTP、HTTPS 或 SOCKS5 地址")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("远程代理必须填写明确的有效端口")
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return nil, errors.New("远程代理必须使用有效 IPv4 或主机名")
		}
	} else if _, e := dnsQuestion(u.Hostname(), 1); e != nil {
		return nil, errors.New("远程代理主机名无效")
	}
	return u, nil
}
func validateConfig(c model.Config, complete bool) error {
	if c.EnforcementMode != "required" && c.EnforcementMode != "proxy-only" {
		return errors.New("请选择代理转发或严格阻断模式")
	}
	if c.AutoRecover && c.EnforcementMode != "proxy-only" {
		return errors.New("自动恢复仅支持代理转发方式；严格阻断需手动重新检查")
	}
	if c.Mode != "clash" && c.Mode != "feilian" && c.Mode != "proxy" && c.Mode != "remote" {
		return errors.New("出口来源无效")
	}
	if c.ProxyPort == 0 {
		return errors.New("守护端口不能为空")
	}
	if len(c.ExpectedIPs) > 16 || len(c.Programs) > 32 || len(c.BundleIDs) > 32 {
		return errors.New("配置项目过多")
	}
	for _, v := range c.ExpectedIPs {
		ip, e := netip.ParseAddr(v)
		if e != nil || !ip.Unmap().IsGlobalUnicast() || ip.IsPrivate() {
			return errors.New("期望出口必须是有效的公网 IP")
		}
	}
	for _, v := range c.Programs {
		if !filepath.IsAbs(v) || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("目标程序必须使用绝对路径")
		}
	}
	for _, v := range c.BundleIDs {
		if v == "" || len(v) > 255 || strings.ContainsAny(v, "/\\\x00\r\n ") {
			return errors.New("应用标识无效")
		}
	}
	if c.ProxyURL != "" {
		var e error
		if c.Mode == "remote" {
			_, e = remoteProxyURL(c.ProxyURL)
		} else {
			_, e = localHTTP(c.ProxyURL)
		}
		if e != nil {
			return e
		}
	}
	for _, raw := range []string{c.ClashControllerURL} {
		if raw != "" {
			if _, e := localHTTP(raw); e != nil {
				return e
			}
		}
	}
	if e := secureURL(c.ProbeURL); e != nil {
		return e
	}
	if c.DNSResolverURL != "" {
		if e := secureURL(c.DNSResolverURL); e != nil {
			return e
		}
	}
	if c.DNSBootstrapIP != "" {
		ip, e := netip.ParseAddr(c.DNSBootstrapIP)
		if e != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return errors.New("DNS 引导地址必须是公网 IP 字面量")
		}
	}
	for _, v := range []string{c.ClashNode, c.ClashSelector, c.TunnelInterface} {
		if len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("出口名称无效")
		}
	}
	if complete {
		for _, raw := range c.ExpectedIPs {
			ip, _ := netip.ParseAddr(raw)
			if !ip.Is4() {
				return errors.New("当前版本仅支持已验证的 IPv4 出口，IPv6 目标保持关闭")
			}
		}
		if len(c.ExpectedIPs) == 0 {
			return errors.New("请先确认并填写固定公网 IP")
		}
		if c.EnforcementMode == "required" && len(c.Programs)+len(c.BundleIDs) == 0 {
			return errors.New("请先选择受保护程序")
		}
		if c.Mode == "clash" && (c.ProxyURL == "" || c.ClashControllerURL == "" || c.ClashNode == "" || c.ClashSelector == "") {
			return errors.New("请填写 Clash 专用入口、控制接口、策略和固定节点")
		}
		if c.Mode == "proxy" && c.ProxyURL == "" {
			return errors.New("请填写已配置的固定本地代理专用入口")
		}
		if c.Mode == "remote" && c.ProxyURL == "" {
			return errors.New("请填写远程代理服务器和端口")
		}
		if c.Mode == "feilian" && (c.TunnelInterface == "" || c.DNSResolverURL == "" || c.DNSBootstrapIP == "") {
			return errors.New("请确认飞连隧道接口及安全 DNS 和引导 IP")
		}
	}
	return nil
}
func loadConfig(path string) (model.Config, error) {
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return defaults(model.Config{Mode: "remote", EnforcementMode: "proxy-only"}), nil
	}
	if e != nil {
		return model.Config{}, errors.New("无法读取配置")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return model.Config{}, errors.New("配置文件格式或大小无效")
	}
	var c model.Config
	d := json.NewDecoder(io.LimitReader(f, 64<<10))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, errors.New("配置文件 JSON 无效")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("配置文件包含多余内容")
	}
	c = defaults(c)
	if e = validateConfig(c, false); e != nil {
		return c, e
	}
	return c, nil
}
func persistConfig(path string, c model.Config) error {
	if path == "" {
		return errors.New("配置路径不能为空")
	}
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return errors.New("无法创建配置目录")
	}
	f, e := os.CreateTemp(dir, ".exitguard-*")
	if e != nil {
		return errors.New("无法创建私有配置文件")
	}
	name := f.Name()
	defer os.Remove(name)
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if e = f.Chmod(0600); e == nil {
		e = json.NewEncoder(f).Encode(c)
	}
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return errors.New("无法安全保存配置")
	}
	if e = os.Rename(name, path); e != nil {
		return errors.New("无法替换配置文件")
	}
	ok = true
	if d, e := os.Open(dir); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
func proxyAddress(c model.Config) string { return fmt.Sprintf("127.0.0.1:%d", c.ProxyPort) }
