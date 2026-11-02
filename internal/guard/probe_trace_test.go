package guard

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"exitguard/internal/model"
)

func readProbeRecords(t *testing.T, s *Service) []map[string]any {
	t.Helper()
	b, e := os.ReadFile(s.configPath + ".diagnostics.jsonl")
	if e != nil {
		t.Fatalf("persistent probe diagnostics missing: %v", e)
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var record map[string]any
		if e := json.Unmarshal([]byte(line), &record); e != nil {
			t.Fatal(e)
		}
		records = append(records, record)
	}
	return records
}

// Removing the instrumentation must lose both the stuck stage and its event ID.
func TestProbeTracePersistsStalledTargetStages(t *testing.T) {
	for _, stage := range []string{"target_tls", "target_http", "target_read"} {
		t.Run(stage, func(t *testing.T) {
			s := configured(t)
			var target string
			roots := x509.NewCertPool()
			if stage == "target_tls" {
				l, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				target = l.Addr().String()
				go func() {
					c, e := l.Accept()
					if e == nil {
						defer c.Close()
						_, _ = c.Read(make([]byte, 4096))
						time.Sleep(150 * time.Millisecond)
					}
				}()
			} else {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if stage == "target_read" {
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
					}
					<-r.Context().Done()
				}))
				defer srv.Close()
				target = strings.TrimPrefix(srv.URL, "https://")
				roots.AddCert(srv.Certificate())
			}
			r := &diagnosticProbeRoute{target: target, roots: roots}
			r.probe = func(ctx context.Context) (string, error) {
				return probeIP(ctx, r, "https://example.com/ip?secret=do-not-log")
			}
			s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			if e := s.Check(ctx); e == nil {
				t.Fatal("stalled probe accepted")
			}
			records := readProbeRecords(t, s)
			last := records[len(records)-1]
			if last["operation"] != "check" || last["stage"] != stage || last["cause"] != "timeout" || last["outcome"] != "failure" {
				t.Fatalf("lost timeout phase: %+v", last)
			}
			id, _ := last["check_id"].(string)
			if id == "" || !strings.Contains(s.Status().Reason, id) || !strings.Contains(s.Status().Reason, stage) {
				t.Fatalf("failure event cannot locate trace: %+v / %+v", last, s.Status())
			}
			encoded, _ := json.Marshal(records)
			if strings.Contains(string(encoded), "example.com") || strings.Contains(string(encoded), "do-not-log") || strings.Contains(string(encoded), target) {
				t.Fatal("trace leaked endpoint/query")
			}
		})
	}
}

type nestedDiagnosticRoute struct {
	diagnosticProbeRoute
	dial func(context.Context, string, string) (net.Conn, error)
}

func (r *nestedDiagnosticRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return r.dial(ctx, network, address)
}

// The outer HTTP trace inherits callbacks into DoH; those must not label DNS as target TLS.
func TestProbeTraceNestedDNSAndLateCallbacks(t *testing.T) {
	for _, phase := range []string{"dns_tls", "dns_http", "dns_read"} {
		t.Run(phase, func(t *testing.T) {
			s := configured(t)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var target, resolver string
			roots := x509.NewCertPool()
			if phase == "dns_tls" {
				l, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				target, resolver = l.Addr().String(), "https://dns-private.invalid/query"
				go func() {
					c, e := l.Accept()
					if e == nil {
						defer c.Close()
						<-release
					}
				}()
			} else {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					if phase == "dns_read" {
						w.Header().Set("Content-Type", "application/dns-message")
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
					}
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}))
				t.Cleanup(srv.Close)
				target, resolver = strings.TrimPrefix(srv.URL, "https://"), srv.URL
				roots.AddCert(srv.Certificate())
			}
			dialDone := make(chan struct{})
			r := &nestedDiagnosticRoute{}
			r.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				defer close(dialDone)
				_, e := resolveHTTPSWithRoots(ctx, "target-private.invalid", resolver, "1.1.1.1", func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp4", target)
				}, roots)
				return nil, e
			}
			r.probe = func(ctx context.Context) (string, error) {
				return probeIP(ctx, r, "https://target-private.invalid/ip?secret=must-not-retain")
			}
			s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			if s.Check(ctx) == nil {
				t.Fatal("stalled DNS accepted")
			}
			records := readProbeRecords(t, s)
			last := records[len(records)-1]
			if last["stage"] != phase || last["cause"] != "timeout" {
				t.Fatalf("nested callbacks confused phase: %+v", last)
			}
			before, _ := os.ReadFile(s.configPath + ".diagnostics.jsonl")
			unblock()
			select {
			case <-dialDone:
			case <-time.After(5 * time.Second):
				t.Fatal("late dial did not unwind")
			}
			after, _ := os.ReadFile(s.configPath + ".diagnostics.jsonl")
			if string(before) != string(after) {
				t.Fatal("late callbacks mutated completed trace")
			}
			for _, span := range last["stages"].([]any) {
				if strings.HasPrefix(span.(map[string]any)["stage"].(string), "target_") {
					t.Fatal("DNS inherited target timing")
				}
			}
		})
	}
}

func TestProbeTraceFreezeAndConcurrentIsolation(t *testing.T) {
	s := configured(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := s.startProbeTrace(context.Background(), diagnosticCandidate, 2, 0, "")
			end := beginProbeStage(ctx, diagnosticSOCKSAuth)
			trace := traceFrom(ctx)
			before := trace.freeze(context.DeadlineExceeded)
			end(errors.New("credential:secret@private.invalid"))
			beginProbeStage(ctx, diagnosticTargetRead)(nil)
			after := trace.freeze(nil)
			if !reflect.DeepEqual(before, after) || before.Stage != "socks_auth" || len(after.Stages) != 1 {
				t.Errorf("trace was mutable or mixed: %+v / %+v", before, after)
			}
			s.finishProbeTrace(ctx, nil)
		}()
	}
	wg.Wait()
	ids := map[string]bool{}
	for _, record := range readProbeRecords(t, s) {
		if record["event"] != "probe" {
			continue
		}
		id := record["check_id"].(string)
		if ids[id] {
			t.Fatal("trace IDs collided")
		}
		ids[id] = true
	}
	if len(ids) != 12 {
		t.Fatalf("missing concurrent records: %d", len(ids))
	}
}

// File errors must neither block admission decisions nor follow links to another file.
func TestProbeLogUnsafeTargetsAndIOFailure(t *testing.T) {
	for _, kind := range []string{"symlink", "backup-symlink", "directory", "parent-symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			protected := filepath.Join(dir, "protected")
			if e := os.WriteFile(protected, []byte("untouched"), 0600); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "config.json.diagnostics.jsonl")
			switch kind {
			case "symlink":
				if e := os.Symlink(protected, path); e != nil {
					t.Fatal(e)
				}
			case "backup-symlink":
				if e := os.Symlink(protected, path+".1"); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "parent-symlink":
				actual := filepath.Join(dir, "actual")
				os.Mkdir(actual, 0700)
				link := filepath.Join(dir, "link")
				if e := os.Symlink(actual, link); e != nil {
					t.Fatal(e)
				}
				path = filepath.Join(link, "config.json.diagnostics.jsonl")
			}
			logger := newProbeLogger(strings.TrimSuffix(path, ".diagnostics.jsonl"))
			logger.marker("process_start")
			b, _ := os.ReadFile(protected)
			if string(b) != "untouched" {
				t.Fatal("logger followed unsafe target")
			}
			if kind == "parent-symlink" {
				if _, e := os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("logger followed unsafe directory link")
				}
			}
			s := configured(t)
			s.diagnostics = logger
			if e := s.Arm(context.Background()); e != nil {
				t.Fatalf("logger failure broke valid admission: %v", e)
			}
		})
	}
}

func TestProbeLogRotationPrivacyAndRestartMarkers(t *testing.T) {
	dir := t.TempDir()
	logger := newProbeLogger(filepath.Join(dir, "config.json"))
	logger.marker("process_start")
	b, e := os.ReadFile(logger.path)
	if e != nil {
		t.Fatal(e)
	}
	padded := []byte(strings.Repeat(string(b), (probeLogLimit/len(b))-1))
	if e := os.WriteFile(logger.path, padded, 0600); e != nil {
		t.Fatal(e)
	}
	logger.write(probeRecord{Event: "probe", Stages: make([]probeSpan, 64)})
	for _, path := range []string{logger.path, logger.path + ".1"} {
		info, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		if info.Size() > 1<<20 || info.Mode().Perm() != 0600 {
			t.Fatalf("unbounded/nonprivate log: %s %v", path, info)
		}
	}
	logger.marker("process_stop")
	second := newProbeLogger(filepath.Join(dir, "config.json"))
	second.marker("process_start")
	b, _ = os.ReadFile(logger.path)
	if !strings.Contains(string(b), "process_stop") || !strings.Contains(string(b), second.processID) || !strings.Contains(string(b), logger.processID) {
		t.Fatal("restart destroyed previous process correlation")
	}
}

func TestProbeTraceAttributesValidatedFailures(t *testing.T) {
	for _, tc := range []struct {
		name, stage, body string
		status            int
	}{
		{"http-status", "target_http", "private-content", 503},
		{"invalid-content", "target_read", "{private-content", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := configured(t)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			r := &diagnosticProbeRoute{target: strings.TrimPrefix(srv.URL, "https://"), roots: roots}
			r.probe = func(ctx context.Context) (string, error) { return probeIP(ctx, r, "https://example.com/") }
			s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
			if s.Check(context.Background()) == nil {
				t.Fatal("invalid response accepted")
			}
			records := readProbeRecords(t, s)
			last := records[len(records)-1]
			if last["stage"] != tc.stage {
				t.Fatalf("validated failure lost phase: %+v", last)
			}
		})
	}
}

func TestProbeTraceRealSOCKSStagesAndScrubbing(t *testing.T) {
	f := newDestinationFixture(t)
	records := readProbeRecords(t, f.s)
	last := records[len(records)-1]
	got := map[string]bool{}
	for _, raw := range last["stages"].([]any) {
		span := raw.(map[string]any)
		got[span["scope"].(string)+":"+span["stage"].(string)] = true
	}
	for _, want := range []string{"dns:proxy_tcp", "dns:socks_negotiation", "dns:socks_auth", "dns:socks_connect", "dns:dns_tls", "dns:dns_http", "dns:dns_read", "target:proxy_tcp", "target:socks_negotiation", "target:socks_auth", "target:socks_connect", "target:target_tls", "target:target_http", "target:target_read"} {
		if !got[want] {
			t.Errorf("real exit verification omitted %s: %+v", want, last)
		}
	}
	b, _ := json.Marshal(records)
	for _, private := range []string{"fixture-user", "fixture-password", "example.com", "203.0.113.7", "203.0.113.53", "127.0.0.1", "dns-query"} {
		if strings.Contains(string(b), private) {
			t.Errorf("private value retained: %s", private)
		}
	}
	f.authDenied.Store(true)
	f.s.health(context.Background())
	records = readProbeRecords(t, f.s)
	last = records[len(records)-1]
	if last["stage"] != "socks_auth" || last["scope"] != "dns" || last["cause"] != "proxy_auth" {
		t.Fatalf("auth rejection lost safe scoped attribution: %+v", last)
	}
}

func TestProbeTraceCancellationKeepsOriginalGeneration(t *testing.T) {
	s := configured(t)
	entered, release := make(chan struct{}), make(chan struct{})
	r := &diagnosticProbeRoute{probe: func(ctx context.Context) (string, error) {
		done := beginProbeStage(ctx, diagnosticSOCKSConnect)
		close(entered)
		<-release
		done(errors.New("username:password@domain.invalid"))
		return "203.0.113.7", nil
	}}
	s.makeRoute = func(model.Config, string) (route, error) { return r, nil }
	done := make(chan error, 1)
	go func() { done <- s.Check(context.Background()) }()
	<-entered
	generation := s.Status().SessionRevision
	s.Disarm()
	before := s.Status()
	close(release)
	if <-done == nil {
		t.Fatal("stale generation accepted")
	}
	if after := s.Status(); !reflect.DeepEqual(before, after) {
		t.Fatal("stale diagnostic completion changed state")
	}
	records := readProbeRecords(t, s)
	last := records[len(records)-1]
	if last["generation"] != float64(generation) || last["cause"] != "cancelled" || last["outcome"] != "failure" {
		t.Fatalf("stale check lost original identity/cancellation: %+v", last)
	}
	b, _ := json.Marshal(records)
	if strings.Contains(string(b), "domain.invalid") || strings.Contains(string(b), "password") {
		t.Fatal("raw stage error retained")
	}
}

func TestProbeTraceRecoveryCorrelationAndFailureEvent(t *testing.T) {
	h := newRecoveryHarness(t, func(int) (route, error) { return recoveredRoute("", context.DeadlineExceeded), nil })
	h.trigger()
	for _, delay := range []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second} {
		tick := h.clock.next(t, delay)
		close(tick.release)
	}
	waitRecoveryState(t, h.s, "blocked")
	var trigger map[string]any
	var retries []map[string]any
	for _, r := range readProbeRecords(t, h.s) {
		if r["operation"] == "health" {
			trigger = r
		}
		if r["operation"] == "recovery" {
			retries = append(retries, r)
		}
	}
	if len(retries) != 3 || trigger == nil {
		t.Fatalf("missing recovery attempt history: %+v", retries)
	}
	for i, r := range retries {
		if r["parent_check_id"] != trigger["check_id"] || r["attempt"] != float64(i+1) || r["generation"] == trigger["generation"] {
			t.Errorf("lost recovery correlation: %+v / %+v", r, trigger)
		}
	}
	if !strings.Contains(h.s.Status().Reason, retries[2]["check_id"].(string)) {
		t.Fatal("recovery failure event cannot locate trace")
	}
}

func TestProbeLogSamplesOnlyOrdinaryHealthSuccesses(t *testing.T) {
	logger := newProbeLogger(filepath.Join(t.TempDir(), "config.json"))
	for i := 0; i < 20; i++ {
		logger.write(probeRecord{Event: "probe", Operation: "health", Outcome: "success"})
	}
	for i := 0; i < 3; i++ {
		logger.write(probeRecord{Event: "probe", Operation: "health", Outcome: "failure"})
	}
	for i := 0; i < 3; i++ {
		logger.write(probeRecord{Event: "probe", Operation: "recovery", Outcome: "success"})
	}
	b, e := os.ReadFile(logger.path)
	if e != nil {
		t.Fatal(e)
	}
	if lines := strings.Count(string(b), "\n"); lines != 7 {
		t.Fatalf("sampling suppressed failures/retries or retained all successes: %d", lines)
	}
}

func TestProbeTraceForwardPersistsOnlyRouteWideFailures(t *testing.T) {
	f := newDestinationFixture(t)
	before := len(readProbeRecords(t, f.s))
	f.healthy(t)
	response, e := f.client.Get("http://localhost.ptlogin2.qq.com/")
	if e == nil {
		response.Body.Close()
	}
	if after := len(readProbeRecords(t, f.s)); after != before {
		t.Fatal("ordinary success or target refusal was persisted")
	}
	f.authDenied.Store(true)
	response, e = f.client.Get("http://example.com/")
	if e == nil {
		response.Body.Close()
	}
	deadline := time.Now().Add(time.Second)
	for len(readProbeRecords(t, f.s)) == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	records := readProbeRecords(t, f.s)
	last := records[len(records)-1]
	if last["operation"] != "forward" || last["stage"] != "socks_auth" || last["scope"] != "dns" || last["cause"] != "proxy_auth" {
		t.Fatalf("route-wide forwarding failure missing trace: %+v", last)
	}
	if !strings.Contains(f.s.Status().Reason, last["check_id"].(string)) {
		t.Fatal("forward failure event cannot locate trace")
	}
}

func TestProbeLogSealsAgainstLateCheckCompletion(t *testing.T) {
	s := configured(t)
	ctx := s.startProbeTrace(context.Background(), diagnosticHealth, 1, 0, "")
	end := beginProbeStage(ctx, diagnosticDNSTLS)
	s.diagnostics.marker("process_stop")
	before, e := os.ReadFile(s.configPath + ".diagnostics.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	end(context.Canceled)
	s.finishProbeTrace(ctx, context.Canceled)
	s.diagnostics.marker("process_stop")
	after, e := os.ReadFile(s.configPath + ".diagnostics.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	if string(before) != string(after) {
		t.Fatal("completed shutdown allowed late diagnostic writes")
	}
}
