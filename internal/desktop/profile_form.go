package desktop

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var errProfileEndpoint = errors.New("请分别填写协议、服务器域名或有效 IPv4、1 至 65535 的端口；服务器中不要包含账户、路径或网址")

// profileEndpoint accepts a bare server field, so URL syntax cannot smuggle
// credentials or change the endpoint assembled by the form.
func profileEndpoint(protocol, host, port string) (string, error) {
	scheme := strings.ToLower(protocol)
	if scheme != "https" && scheme != "http" && scheme != "socks5" {
		return "", errProfileEndpoint
	}
	host, port = strings.ToLower(strings.TrimSpace(host)), strings.TrimSpace(port)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, ":/@?#\\%[]") || strings.IndexFunc(host, unicode.IsSpace) >= 0 {
		return "", errProfileEndpoint
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() == nil {
			return "", errProfileEndpoint
		}
		host = ip.String()
	} else {
		numeric := true
		for _, r := range host {
			if (r < '0' || r > '9') && r != '.' {
				numeric = false
				break
			}
		}
		if numeric {
			return "", errProfileEndpoint
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errProfileEndpoint
			}
			for _, r := range label {
				if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
					return "", errProfileEndpoint
				}
			}
		}
	}
	if port == "" {
		return "", errProfileEndpoint
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", errProfileEndpoint
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errProfileEndpoint
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func splitProfileEndpoint(raw string) (protocol, host, port string, err error) {
	u, e := url.Parse(raw)
	if e != nil || u == nil || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "", "", errProfileEndpoint
	}
	protocol, host, port = strings.ToUpper(u.Scheme), u.Hostname(), u.Port()
	if _, e = profileEndpoint(protocol, host, port); e != nil {
		return "", "", "", errProfileEndpoint
	}
	return protocol, host, port, nil
}
