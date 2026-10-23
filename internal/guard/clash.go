package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"exitguard/internal/model"
)

type clashProxy struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

func verifyClash(ctx context.Context, c model.Config, secret string) (string, error) {
	base, e := localHTTP(c.ClashControllerURL)
	if e != nil {
		return "", e
	}
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("控制接口禁止重定向") }, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}}
	get := func(name string) (clashProxy, error) {
		var p clashProxy
		u := *base
		u.Path = "/proxies/" + name
		u.RawPath = "/proxies/" + url.PathEscape(name) // Escape names once; URL.String validates RawPath.
		req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if e != nil {
			return p, errors.New("控制请求无效")
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, e := client.Do(req)
		if e != nil {
			return p, errors.New("Clash 控制接口不可达")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return p, errors.New("Clash 控制接口拒绝读取")
		}
		b, e := readBounded(resp.Body, 64<<10)
		if e != nil {
			return p, e
		}
		if json.Unmarshal(b, &p) != nil {
			return p, errors.New("Clash 控制接口格式不兼容")
		}
		return p, nil
	}
	selector, e := get(c.ClashSelector)
	if e != nil {
		return "", e
	}
	if !strings.EqualFold(selector.Type, "selector") || selector.Now != c.ClashNode || len(selector.All) != 1 || selector.All[0] != c.ClashNode {
		return "", errors.New("Clash 专用策略必须只包含指定的一个固定节点")
	}
	node, e := get(c.ClashNode)
	if e != nil {
		return "", e
	}
	if strings.EqualFold(c.ClashNode, "direct") || strings.EqualFold(c.ClashNode, "reject") || len(node.All) != 0 || node.Now != "" {
		return "", errors.New("Clash 固定节点不能是直连或嵌套策略")
	}
	switch strings.ToLower(node.Type) {
	case "ss", "shadowsocks", "ssr", "shadowsocksr", "vmess", "vless", "trojan", "socks5", "http", "snell", "wireguard", "hysteria", "hysteria2", "tuic", "ssh":
	default:
		return "", errors.New("Clash 节点类型不是已支持的固定叶节点")
	}
	data, _ := json.Marshal([]clashProxy{selector, node})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
