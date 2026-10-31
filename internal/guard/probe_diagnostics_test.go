package guard

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"exitguard/internal/model"
)

type diagnosticProbeRoute struct {
	testRoute
	target  string
	roots   *x509.CertPool
	dialErr error
	probe   func(context.Context) (string, error)
}

func (r *diagnosticProbeRoute) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	if r.dialErr != nil {
		return nil, r.dialErr
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp4", r.target)
}
func (r *diagnosticProbeRoute) transportRoots() *x509.CertPool { return r.roots }
func (r *diagnosticProbeRoute) Probe(ctx context.Context, _ string) (string, error) {
	return r.probe(ctx)
}

func TestProbeDiagnosticsDistinguishSafeFailureCauses(t *testing.T) {
	const private = "must-not-echo-secret-token"
	for _, tc := range []struct {
		name, want, body string
		status           int
		dialErr          error
		timeout          bool
		truncated        bool
		untrusted        bool
	}{
		{name: "http-429", want: "HTTP 429", status: 429, body: private},
		{name: "http-503", want: "HTTP 503", status: 503, body: private},
		{name: "timeout", want: "超时", timeout: true},
		{name: "upstream-auth", want: "SOCKS5 代理握手或认证失败", dialErr: &upstreamError{"SOCKS5 代理握手或认证失败"}},
		{name: "upstream-tls", want: "HTTPS 代理证书或 TLS 握手验证失败", dialErr: &upstreamError{"HTTPS 代理证书或 TLS 握手验证失败"}},
		{name: "upstream-transport", want: "指定代理上游不可达", dialErr: &upstreamError{"指定代理上游不可达"}},
		{name: "raw-network", want: "网络", dialErr: errors.New("https://fixture-user:" + private + "@private.invalid/raw-header")},
		{name: "unrecognized-upstream-error", want: "网络", dialErr: &upstreamError{private}},
		{name: "target-tls", want: "TLS 证书验证失败", untrusted: true, status: 200},
		{name: "invalid-json", want: "无效内容", status: 200, body: `{"ip":"` + private},
		{name: "invalid-ip", want: "有效公网地址", status: 200, body: private},
		{name: "body-limit", want: "大小限制", status: 200, body: strings.Repeat(private, 200)},
		{name: "body-read", want: "响应读取失败", status: 200, body: private, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if tc.timeout {
					<-req.Context().Done()
					return
				}
				if tc.truncated {
					w.Header().Set("Content-Length", "4090")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			roots := x509.NewCertPool()
			if !tc.untrusted {
				roots.AddCert(srv.Certificate())
			}
			r := &diagnosticProbeRoute{target: strings.TrimPrefix(srv.URL, "https://"), roots: roots, dialErr: tc.dialErr}
			ctx := context.Background()
			if tc.timeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			ip, e := probeIP(ctx, r, "https://example.com/ip?private="+private)
			if e == nil || ip != "" || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("want distinct %q diagnostic, got ip=%q err=%v", tc.want, ip, e)
			}
			var diagnostic *probeError
			if !errors.As(e, &diagnostic) {
				t.Fatalf("probe failure is not typed: %T", e)
			}
			if strings.Contains(e.Error(), private) || strings.Contains(e.Error(), "private.invalid") || strings.Contains(e.Error(), "fixture-user") || strings.Contains(e.Error(), "https://") {
				t.Fatalf("probe error reflected private source data: %v", e)
			}
		})
	}
}

func TestProbeMismatchPreservesObservedIPAndExpectedPolicy(t *testing.T) {
	for _, operation := range []string{"check", "arm", "health"} {
		t.Run(operation, func(t *testing.T) {
			s := configured(t)
			want := s.Config().ExpectedIPs
			r := &diagnosticProbeRoute{probe: func(context.Context) (string, error) { return "198.51.100.9", nil }}
			s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
			if operation == "health" {
				r.probe = func(context.Context) (string, error) { return "203.0.113.7", nil }
				if e := s.Arm(context.Background()); e != nil {
					t.Fatal(e)
				}
				r.probe = func(context.Context) (string, error) { return "198.51.100.9", nil }
				s.health(context.Background())
			} else {
				var e error
				if operation == "arm" {
					e = s.Arm(context.Background())
				} else {
					e = s.Check(context.Background())
				}
				if e == nil {
					t.Fatal("IP mismatch accepted")
				}
			}
			st := s.Status()
			if st.State != "blocked" || st.ObservedIP != "198.51.100.9" || !strings.Contains(st.Reason, "与期望 IP 不符") || strings.Contains(st.Reason, "检查失败") {
				t.Fatalf("valid mismatch not distinguished and retained: %+v", st)
			}
			if !reflect.DeepEqual(s.Config().ExpectedIPs, want) {
				t.Fatal("observed mismatch changed expected policy")
			}
		})
	}
}

func TestProbeFailureReasonIsSanitizedInCheckHealthAndCandidate(t *testing.T) {
	const private = "raw-network-credential-must-not-echo"
	for _, operation := range []string{"check", "health", "candidate"} {
		for _, tc := range []struct {
			failure error
			want    string
		}{
			{context.DeadlineExceeded, "超时"},
			{&probeError{kind: probeHTTPStatus, status: 429}, "HTTP 429"},
			{&probeError{kind: probeHTTPStatus, status: 503}, "HTTP 503"},
			{&upstreamError{"SOCKS5 代理握手或认证失败"}, "SOCKS5 代理握手或认证失败"},
			{errors.New(private), "网络"},
		} {
			t.Run(operation+"/"+tc.want, func(t *testing.T) {
				s := configured(t)
				r := &diagnosticProbeRoute{probe: func(context.Context) (string, error) { return "", tc.failure }}
				s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
				switch operation {
				case "health":
					r.probe = func(context.Context) (string, error) { return "203.0.113.7", nil }
					if e := s.Arm(context.Background()); e != nil {
						t.Fatal(e)
					}
					r.probe = func(context.Context) (string, error) { return "", tc.failure }
					s.health(context.Background())
				case "candidate":
					if _, e := s.ProbeCandidate(context.Background()); e == nil {
						t.Fatal("failed candidate accepted")
					}
				default:
					if e := s.Check(context.Background()); e == nil {
						t.Fatal("failed check accepted")
					}
				}
				if st := s.Status(); st.State != "blocked" || !strings.Contains(st.Reason, tc.want) || strings.Contains(st.Reason, "与期望 IP 不符") {
					t.Fatalf("failure cause collapsed: %+v", st)
				}
				out, _ := json.Marshal([]any{s.Status(), s.Events()})
				if strings.Contains(string(out), private) {
					t.Fatal("private raw probe error reflected in status/events")
				}
			})
		}
	}
}

func TestStaleProbeMismatchCannotOverwriteCurrentState(t *testing.T) {
	for _, operation := range []string{"check", "health"} {
		t.Run(operation, func(t *testing.T) {
			s := configured(t)
			entered, release := make(chan struct{}), make(chan struct{})
			r := &diagnosticProbeRoute{probe: func(context.Context) (string, error) { return "203.0.113.7", nil }}
			s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
			if operation == "health" {
				if e := s.Arm(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			r.probe = func(context.Context) (string, error) { close(entered); <-release; return "198.51.100.9", nil }
			done := make(chan struct{})
			go func() {
				defer close(done)
				if operation == "health" {
					s.health(context.Background())
				} else {
					s.Check(context.Background())
				}
			}()
			<-entered
			s.Disarm()
			before := s.Status()
			close(release)
			<-done
			if after := s.Status(); !reflect.DeepEqual(after, before) {
				t.Fatalf("stale mismatch overwrote current state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestCancelledProbeCannotRecordReturnedMismatch(t *testing.T) {
	s := configured(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &diagnosticProbeRoute{probe: func(context.Context) (string, error) { cancel(); return "198.51.100.9", nil }}
	s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
	if e := s.Check(ctx); e == nil {
		t.Fatal("cancelled mismatch check accepted")
	}
	if st := s.Status(); st.State != "blocked" || st.ObservedIP != "" || !strings.Contains(st.Reason, "取消") {
		t.Fatalf("cancelled probe recorded mismatch or unclear cause: %+v", st)
	}
}
