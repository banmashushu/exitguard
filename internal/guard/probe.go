package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func probeIP(ctx context.Context, r interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}, raw string) (string, error) {
	if _, e := safeRequestURL(raw); e != nil {
		return "", e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return "", errors.New("探测地址无效")
	}
	req.Header.Set("Accept", "application/json, text/plain")
	resp, e := routeClient(r).Do(req)
	if e != nil {
		return "", errors.New("无法通过指定出口完成公网探测")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("公网探测未成功")
	}
	b, e := readBounded(resp.Body, 4096)
	if e != nil {
		return "", e
	}
	rawIP := strings.TrimSpace(string(b))
	if strings.HasPrefix(rawIP, "{") {
		var v struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(b, &v) != nil {
			return "", errors.New("公网探测返回无效内容")
		}
		rawIP = v.IP
	}
	ip, e := netip.ParseAddr(rawIP)
	if e != nil || !ip.Unmap().IsGlobalUnicast() || ip.IsPrivate() {
		return "", errors.New("公网探测未返回有效公网地址")
	}
	return ip.Unmap().String(), nil
}
