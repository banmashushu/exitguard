package guard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

func dnsQuestion(host string, qtype uint16) ([]byte, error) {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || (qtype != 1 && qtype != 28) {
		return nil, errors.New("DNS 查询无效")
	}
	b := make([]byte, 12)
	if _, e := rand.Read(b[:2]); e != nil {
		return nil, e
	}
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("DNS 主机名无效")
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return nil, errors.New("DNS 主机名必须使用 ASCII / punycode")
			}
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b, nil
}

// dnsName returns the expanded lower-case name and the position after its encoding.
func dnsName(b []byte, offset int) (string, int, error) {
	var labels []string
	next := -1
	seen := map[int]bool{}
	total := 0
	for steps := 0; steps < 128; steps++ {
		if offset < 0 || offset >= len(b) || seen[offset] {
			return "", 0, errors.New("DNS 名称编码无效")
		}
		seen[offset] = true
		n := int(b[offset])
		offset++
		if n == 0 {
			if next < 0 {
				next = offset
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		if n&0xc0 == 0xc0 {
			if offset >= len(b) {
				break
			}
			pointer := ((n & 63) << 8) | int(b[offset])
			if next < 0 {
				next = offset + 1
			}
			offset = pointer
			continue
		}
		if n > 63 || offset+n > len(b) {
			break
		}
		total += n + 1
		if total > 254 {
			break
		}
		labels = append(labels, string(b[offset:offset+n]))
		offset += n
	}
	return "", 0, errors.New("DNS 名称编码无效")
}
func dnsAnswers(b, query []byte, qtype uint16) ([]string, error) {
	bad := errors.New("安全 DNS 返回无效响应")
	if len(b) < 12 || len(query) < 12 || !bytes.Equal(b[:2], query[:2]) || binary.BigEndian.Uint16(b[2:4])&0xfa00 != 0x8000 || binary.BigEndian.Uint16(b[4:6]) != 1 {
		return nil, bad
	}
	rcode := binary.BigEndian.Uint16(b[2:4]) & 15
	if rcode != 0 && rcode != 3 {
		return nil, bad
	}
	qn, qend, e := dnsName(query, 12)
	if e != nil {
		return nil, bad
	}
	name, end, e := dnsName(b, 12)
	if e != nil || name != qn || end+4 > len(b) || qend+4 > len(query) || !bytes.Equal(b[end:end+4], query[qend:qend+4]) {
		return nil, bad
	}
	answers := int(binary.BigEndian.Uint16(b[6:8]))
	count := answers + int(binary.BigEndian.Uint16(b[8:10])) + int(binary.BigEndian.Uint16(b[10:12]))
	if count > 256 {
		return nil, bad
	}
	offset := end + 4
	type record struct {
		name      string
		kind      uint16
		data      []byte
		dataStart int
	}
	records := make([]record, 0, answers)
	for i := 0; i < count; i++ {
		owner, pos, e := dnsName(b, offset)
		if e != nil || pos+10 > len(b) {
			return nil, bad
		}
		kind := binary.BigEndian.Uint16(b[pos : pos+2])
		class := binary.BigEndian.Uint16(b[pos+2 : pos+4])
		length := int(binary.BigEndian.Uint16(b[pos+8 : pos+10]))
		start := pos + 10
		offset = start + length
		if offset > len(b) || i < answers && class != 1 {
			return nil, bad
		}
		if i < answers {
			records = append(records, record{owner, kind, b[start:offset], start})
		}
	}
	if offset != len(b) {
		return nil, bad
	}
	allowed := map[string]bool{qn: true}
	for passes := 0; passes < 16; passes++ {
		changed := false
		for _, rr := range records {
			if rr.kind == 5 && allowed[rr.name] {
				alias, after, e := dnsName(b, rr.dataStart)
				if e != nil || after != rr.dataStart+len(rr.data) {
					return nil, bad
				}
				if !allowed[alias] {
					allowed[alias] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	var ips []string
	relatedAnswers, rejectedAddress := 0, false
	for _, rr := range records {
		if rr.kind != qtype || !allowed[rr.name] {
			continue
		}
		var ip netip.Addr
		if qtype == 1 && len(rr.data) == 4 {
			var a [4]byte
			copy(a[:], rr.data)
			ip = netip.AddrFrom4(a)
		} else if qtype == 28 && len(rr.data) == 16 {
			var a [16]byte
			copy(a[:], rr.data)
			ip = netip.AddrFrom16(a)
		} else {
			return nil, bad
		}
		relatedAnswers++
		if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.IsLinkLocalUnicast() {
			rejectedAddress = true
			continue
		}
		ips = append(ips, ip.String())
	}
	if rcode == 3 {
		if relatedAnswers != 0 {
			return nil, bad
		}
		return nil, &destinationError{"安全 DNS 确认目标域名不存在"}
	}
	if rejectedAddress {
		// A valid reply naming a disallowed address is a target-policy refusal,
		// not evidence of a damaged DNS channel. Reject mixed answers as a whole,
		// only after every related record has been validated above.
		return nil, &destinationError{"安全 DNS 目标地址不在允许转发范围"}
	}
	return ips, nil
}
func resolveHTTPS(ctx context.Context, host, resolver, bootstrap string, dial func(context.Context, string, string) (net.Conn, error)) ([]string, error) {
	return resolveHTTPSWithRoots(ctx, host, resolver, bootstrap, dial, nil)
}
func resolveHTTPSWithRoots(ctx context.Context, host, resolver, bootstrap string, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) ([]string, error) {
	u, e := url.Parse(resolver)
	if e != nil || secureURL(resolver) != nil {
		return nil, errors.New("安全 DNS 地址无效")
	}
	ip, e := netip.ParseAddr(bootstrap)
	if e != nil || !ip.Is4() {
		return nil, errors.New("安全 DNS 引导地址必须为 IPv4 字面量")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	endpoint := net.JoinHostPort(ip.String(), port)
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("安全 DNS 禁止重定向") }, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		wanted := net.JoinHostPort(u.Hostname(), port)
		if !strings.EqualFold(address, wanted) {
			return nil, errors.New("安全 DNS 不允许其他连接")
		}
		connection, err := dial(ctx, "tcp", endpoint)
		if err != nil {
			return nil, dnsDialFailure(err)
		}
		return connection, nil
	}, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10}}
	return queryIPv4(ctx, host, resolver, client)
}
func queryIPv4(ctx context.Context, host, resolver string, client *http.Client) ([]string, error) {
	q, e := dnsQuestion(host, 1)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", resolver, bytes.NewReader(q))
	if e != nil {
		return nil, errors.New("安全 DNS 请求无效")
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	var connected atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }}))
	resp, e := client.Do(req)
	established := connected.Load()
	if e != nil {
		var upstream *upstreamError
		if errors.As(e, &upstream) {
			return nil, upstream
		}
		var known *forwardError
		if errors.As(e, &known) {
			return nil, known
		}
		var destination *destinationError
		if errors.As(e, &destination) {
			return nil, destination
		}
		failure := transportFailure(stageDNS, e, established)
		failure.local = established
		return nil, failure
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &forwardError{stage: stageDNS, cause: causeHTTPStatus, status: resp.StatusCode, local: established}
	}
	contentType, _, mimeErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mimeErr != nil || contentType != "application/dns-message" {
		return nil, &forwardError{stage: stageDNS, cause: causeInvalidResponse}
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if len(data) > 64<<10 {
		return nil, &forwardError{stage: stageDNS, cause: causeInvalidResponse}
	}
	if e != nil {
		failure := transportFailure(stageDNS, e, true)
		failure.local = established
		return nil, failure
	}
	ips, e := dnsAnswers(data, q, 1)
	if e != nil {
		var unavailable *destinationError
		if errors.As(e, &unavailable) {
			return nil, unavailable
		}
		return nil, &forwardError{stage: stageDNS, cause: causeInvalidResponse}
	}
	if len(ips) == 0 {
		return nil, &destinationError{"安全 DNS 未返回目标的可用 IPv4 地址"}
	}
	return ips, nil
}
