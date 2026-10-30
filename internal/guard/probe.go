package guard

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type probeFailure uint8

const (
	probeNetworkFailure probeFailure = iota
	probeTimeout
	probeCancelled
	probeInvalidAddress
	probeHTTPStatus
	probeBodyRead
	probeBodyLimit
	probeInvalidContent
	probeInvalidIP
	probeUpstreamUnavailable
	probeUpstreamTLS
	probeUpstreamSOCKSAuth
	probeUpstreamSOCKSProtocol
	probeTLSFailure
	probeDestinationUnavailable
)

// A probeError contains only an enumerated cause and an HTTP status number.
// Raw URLs, response bodies, credentials, and transport errors are not retained.
type probeError struct {
	kind   probeFailure
	status int
}

func (e *probeError) Error() string {
	switch e.kind {
	case probeTimeout:
		return "公网探测超时"
	case probeCancelled:
		return "公网探测已取消"
	case probeInvalidAddress:
		return "公网探测地址无效"
	case probeHTTPStatus:
		return fmt.Sprintf("公网探测收到 HTTP %d", e.status)
	case probeBodyRead:
		return "公网探测响应读取失败"
	case probeBodyLimit:
		return "公网探测响应超过大小限制"
	case probeInvalidContent:
		return "公网探测返回无效内容"
	case probeInvalidIP:
		return "公网探测未返回有效公网地址"
	case probeUpstreamUnavailable:
		return "指定代理上游不可达"
	case probeUpstreamTLS:
		return "HTTPS 代理证书或 TLS 握手验证失败"
	case probeUpstreamSOCKSAuth:
		return "SOCKS5 代理握手或认证失败"
	case probeUpstreamSOCKSProtocol:
		return "SOCKS5 代理返回一般故障或不支持的连接响应"
	case probeTLSFailure:
		return "公网探测 TLS 证书验证失败"
	case probeDestinationUnavailable:
		return "指定出口无法连接公网探测目标"
	default:
		return "公网探测网络请求失败"
	}
}

func safeProbeError(e error) *probeError {
	var known *probeError
	if errors.As(e, &known) {
		return known
	}
	var timed net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &timed) && timed.Timeout() {
		return &probeError{kind: probeTimeout}
	}
	if errors.Is(e, context.Canceled) {
		return &probeError{kind: probeCancelled}
	}
	var upstream *upstreamError
	if errors.As(e, &upstream) {
		// Match fixed internal constants; never reflect an arbitrary error string.
		switch upstream.reason {
		case "指定代理上游不可达":
			return &probeError{kind: probeUpstreamUnavailable}
		case "HTTPS 代理证书或 TLS 握手验证失败":
			return &probeError{kind: probeUpstreamTLS}
		case "SOCKS5 代理握手或认证失败":
			return &probeError{kind: probeUpstreamSOCKSAuth}
		case "SOCKS5 代理返回一般故障或不支持的连接响应":
			return &probeError{kind: probeUpstreamSOCKSProtocol}
		}
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(e, &certificate) {
		return &probeError{kind: probeTLSFailure}
	}
	var unavailable *destinationError
	if errors.As(e, &unavailable) {
		return &probeError{kind: probeDestinationUnavailable}
	}
	return &probeError{kind: probeNetworkFailure}
}

func validProbeIP(raw string) (string, error) {
	ip, e := netip.ParseAddr(raw)
	if e != nil || !ip.Unmap().IsGlobalUnicast() || ip.Unmap().IsPrivate() {
		return "", &probeError{kind: probeInvalidIP}
	}
	return ip.Unmap().String(), nil
}

func probeIP(ctx context.Context, r interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}, raw string) (string, error) {
	if _, e := safeRequestURL(raw); e != nil {
		return "", &probeError{kind: probeInvalidAddress}
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return "", &probeError{kind: probeInvalidAddress}
	}
	req.Header.Set("Accept", "application/json, text/plain")
	resp, e := routeClient(r).Do(req)
	if e != nil {
		return "", safeProbeError(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", &probeError{kind: probeHTTPStatus, status: resp.StatusCode}
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil {
		if cause := safeProbeError(e); cause.kind == probeTimeout || cause.kind == probeCancelled {
			return "", cause
		}
		return "", &probeError{kind: probeBodyRead}
	}
	if len(b) > 4096 {
		return "", &probeError{kind: probeBodyLimit}
	}
	rawIP := strings.TrimSpace(string(b))
	if strings.HasPrefix(rawIP, "{") {
		var v struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(b, &v) != nil {
			return "", &probeError{kind: probeInvalidContent}
		}
		rawIP = v.IP
	}
	return validProbeIP(rawIP)
}
