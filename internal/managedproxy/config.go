package managedproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"exitguard/internal/subscription"
)

const leafName = "exitguard-selected"

func itoa(n int) string { return strconv.Itoa(n) }
func validateNode(n Node) error {
	if err := subscription.ValidateCanonicalNode(n.Config); err != nil {
		return ErrNode
	}
	b, err := json.Marshal(n.Config)
	if err != nil {
		return ErrNode
	}
	h := sha256.Sum256(b)
	if n.Identity != hex.EncodeToString(h[:]) {
		return ErrNode
	}
	return nil
}

type runtimeConfig struct {
	Hosts         map[string]string `json:"hosts"`
	GeoAutoUpdate bool              `json:"geo-auto-update"`
	Port          int               `json:"port"`
	SocksPort     int               `json:"socks-port"`
	MixedPort     int               `json:"mixed-port"`
	AllowLAN      bool              `json:"allow-lan"`
	BindAddress   string            `json:"bind-address"`
	Mode          string            `json:"mode"`
	LogLevel      string            `json:"log-level"`
	IPv6          bool              `json:"ipv6"`
	FindProcess   string            `json:"find-process-mode"`
	Controller    string            `json:"external-controller"`
	Secret        string            `json:"secret"`
	DNS           map[string]bool   `json:"dns"`
	Profile       map[string]bool   `json:"profile"`
	Proxies       []map[string]any  `json:"proxies"`
	Listeners     []runtimeListener `json:"listeners"`
	Rules         []string          `json:"rules"`
}
type runtimeListener struct {
	Name   string        `json:"name"`
	Type   string        `json:"type"`
	Port   int           `json:"port"`
	Listen string        `json:"listen"`
	Proxy  string        `json:"proxy"`
	Users  []runtimeUser `json:"users"`
}
type runtimeUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func generateConfig(n Node, pinned string, port, controller int, user, pass, secret string) ([]byte, error) {
	if err := validateNode(n); err != nil {
		return nil, err
	}
	leaf := make(map[string]any, len(n.Config)+1)
	for k, v := range n.Config {
		leaf[k] = v
	}
	leaf["name"] = leafName
	c := runtimeConfig{Hosts: map[string]string{n.Config["server"].(string): pinned}, BindAddress: "127.0.0.1", Mode: "rule", LogLevel: "silent", FindProcess: "off", Controller: "127.0.0.1:" + itoa(controller), Secret: secret, DNS: map[string]bool{"enable": false}, Profile: map[string]bool{"store-selected": false, "store-fake-ip": false}, Proxies: []map[string]any{leaf}, Listeners: []runtimeListener{{Name: "exitguard-private", Type: "http", Port: port, Listen: "127.0.0.1", Proxy: leafName, Users: []runtimeUser{{user, pass}}}}, Rules: []string{"MATCH,REJECT"}}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, ErrNode
	}
	if err = validateRuntimeConfig(b); err != nil {
		return nil, err
	}
	return b, nil
}
func validateRuntimeConfig(b []byte) error {
	if len(b) > 128*1024 {
		return ErrNode
	}
	var c runtimeConfig
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return ErrNode
	}
	if c.GeoAutoUpdate || len(c.Hosts) != 1 || c.Port != 0 || c.SocksPort != 0 || c.MixedPort != 0 || c.AllowLAN || c.BindAddress != "127.0.0.1" || c.Mode != "rule" || c.LogLevel != "silent" || c.IPv6 || c.FindProcess != "off" || len(c.Secret) < 24 || len(c.DNS) != 1 || c.DNS["enable"] || len(c.Profile) != 2 || c.Profile["store-selected"] || c.Profile["store-fake-ip"] || len(c.Rules) != 1 || c.Rules[0] != "MATCH,REJECT" || len(c.Proxies) != 1 || len(c.Listeners) != 1 {
		return ErrNode
	}
	if _, ok := c.DNS["enable"]; !ok {
		return ErrNode
	}
	for _, k := range []string{"store-selected", "store-fake-ip"} {
		if _, ok := c.Profile[k]; !ok {
			return ErrNode
		}
	}
	var cp int
	if _, err := fmt.Sscanf(c.Controller, "127.0.0.1:%d", &cp); err != nil || cp < 1024 || cp > 65535 || c.Controller != "127.0.0.1:"+itoa(cp) {
		return ErrNode
	}
	l := c.Listeners[0]
	if l.Name != "exitguard-private" || l.Type != "http" || l.Listen != "127.0.0.1" || l.Port < 1024 || l.Port > 65535 || l.Port == cp || l.Proxy != leafName || len(l.Users) != 1 || len(l.Users[0].Username) < 1 || len(l.Users[0].Password) < 1 {
		return ErrNode
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(b, canonical) {
		return ErrNode
	}
	leaf := c.Proxies[0]
	server, _ := leaf["server"].(string)
	pinned, ok := c.Hosts[server]
	ip, err := netip.ParseAddr(pinned)
	if !ok || err != nil || !ip.Is4() {
		return ErrNode
	}
	if leaf["name"] != leafName {
		return ErrNode
	}
	delete(leaf, "name")
	return subscription.ValidateCanonicalNode(leaf)
}
func attestController(ctx context.Context, client *http.Client, port int, secret string, n Node) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+itoa(port)+"/proxies/"+leafName, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	var node struct{ Name, Type string }
	if json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&node) != nil {
		return false
	}
	return node.Name == leafName && strings.EqualFold(node.Type, coreType(n.Config["type"].(string)))
}
func coreType(t string) string {
	switch t {
	case "http":
		return "Http"
	case "socks5":
		return "Socks5"
	case "ss":
		return "Shadowsocks"
	case "ssr":
		return "ShadowsocksR"
	}
	return t
}
func attestListener(ctx context.Context, client *http.Client, l *Lease) bool {
	// An unauthenticated CONNECT must be rejected locally. It cannot reach any
	// endpoint, and confirms this listener has its expected private auth policy.
	req, err := http.NewRequestWithContext(ctx, "CONNECT", l.URL, nil)
	if err != nil {
		return false
	}
	req.Host = "127.0.0.1:1"
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 407
}
