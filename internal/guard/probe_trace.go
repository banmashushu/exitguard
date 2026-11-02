package guard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

// Diagnostics accept only these internal enums, never transport strings.
type probeStage uint8

const (
	diagnosticVerify probeStage = iota
	diagnosticProxyLookup
	diagnosticProxyTCP
	diagnosticProxyTLS
	diagnosticSOCKSNegotiation
	diagnosticSOCKSAuth
	diagnosticSOCKSConnect
	diagnosticHTTPConnect
	diagnosticDNSTLS
	diagnosticDNSHTTP
	diagnosticDNSRead
	diagnosticTargetTLS
	diagnosticTargetHTTP
	diagnosticTargetRead
	diagnosticTargetTCP
)

func (s probeStage) String() string {
	names := [...]string{"verify", "proxy_lookup", "proxy_tcp", "proxy_tls", "socks_negotiation", "socks_auth", "socks_connect", "http_connect", "dns_tls", "dns_http", "dns_read", "target_tls", "target_http", "target_read", "target_tcp"}
	if int(s) >= len(names) {
		return "verify"
	}
	return names[s]
}

type probeOperation uint8

const (
	diagnosticCheck probeOperation = iota
	diagnosticArm
	diagnosticHealth
	diagnosticCandidate
	diagnosticRecovery
	diagnosticForward
)

func (o probeOperation) String() string {
	names := [...]string{"check", "arm", "health", "candidate", "recovery", "forward"}
	if int(o) >= len(names) {
		return "check"
	}
	return names[o]
}

type probeSpan struct {
	Stage     string `json:"stage"`
	Scope     string `json:"scope"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Outcome   string `json:"outcome"`
	Cause     string `json:"cause,omitempty"`
	start     time.Time
	ended     bool
}
type probeRecord struct {
	Version           int         `json:"version"`
	Event             string      `json:"event"`
	Time              string      `json:"time"`
	ProcessID         string      `json:"process_id"`
	CheckID           string      `json:"check_id,omitempty"`
	ParentCheckID     string      `json:"parent_check_id,omitempty"`
	Operation         string      `json:"operation,omitempty"`
	Generation        uint64      `json:"generation,omitempty"`
	Attempt           int         `json:"attempt,omitempty"`
	ElapsedMS         int64       `json:"elapsed_ms,omitempty"`
	BudgetMS          int64       `json:"budget_ms,omitempty"`
	HealthGapMS       int64       `json:"health_gap_ms,omitempty"`
	ActiveConnections int         `json:"active_connections"`
	Outcome           string      `json:"outcome,omitempty"`
	Stage             string      `json:"stage,omitempty"`
	Scope             string      `json:"scope,omitempty"`
	Cause             string      `json:"cause,omitempty"`
	HTTPStatus        int         `json:"http_status,omitempty"`
	Stages            []probeSpan `json:"stages,omitempty"`
}
type probeTrace struct {
	mu     sync.Mutex
	start  time.Time
	record probeRecord
	frozen bool
}
type probeTraceKey struct{}
type probeScopeKey struct{}

func traceFrom(ctx context.Context) *probeTrace {
	trace, _ := ctx.Value(probeTraceKey{}).(*probeTrace)
	return trace
}
func beginProbeStage(ctx context.Context, stage probeStage) func(error) {
	t := traceFrom(ctx)
	if t == nil {
		return func(error) {}
	}
	t.mu.Lock()
	if t.frozen || len(t.record.Stages) >= 64 {
		t.mu.Unlock()
		return func(error) {}
	}
	scope := "target"
	if dns, _ := ctx.Value(probeScopeKey{}).(bool); dns {
		scope = "dns"
	}
	i := len(t.record.Stages)
	t.record.Stages = append(t.record.Stages, probeSpan{Stage: stage.String(), Scope: scope, start: time.Now()})
	t.mu.Unlock()
	return func(e error) {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.frozen || t.record.Stages[i].ended {
			return
		}
		span := &t.record.Stages[i]
		span.ElapsedMS, span.ended, span.Outcome = time.Since(span.start).Milliseconds(), true, "success"
		if e != nil {
			span.Outcome, span.Cause = "failure", probeCause(e)
		}
	}
}

func probeCause(e error) string {
	if e == nil {
		return ""
	}
	if errors.Is(e, errRecoveryIP) || errors.Is(e, errProbeMismatch) {
		return "ip_mismatch"
	}
	if errors.Is(e, errRecoveryPath) {
		return "path_changed"
	}
	p := safeProbeError(e)
	switch p.kind {
	case probeTimeout:
		return "timeout"
	case probeCancelled:
		return "cancelled"
	case probeHTTPStatus:
		return "http_status"
	case probeBodyRead, probeNetworkFailure, probeUpstreamUnavailable:
		return "transport"
	case probeTLSFailure, probeTLSProtocolFailure, probeUpstreamTLS:
		return "tls"
	case probeUpstreamSOCKSAuth:
		return "proxy_auth"
	case probeUpstreamSOCKSProtocol:
		return "proxy_protocol"
	case probeInvalidAddress:
		return "invalid_address"
	case probeBodyLimit:
		return "body_limit"
	case probeInvalidIP:
		return "invalid_ip"
	case probeInvalidContent:
		return "invalid_response"
	case probeDestinationUnavailable:
		return "destination"
	case probeForwardFailure:
		if p.forward != nil {
			switch p.forward.cause {
			case causeTimeout:
				return "timeout"
			case causeCancelled:
				return "cancelled"
			case causeInterrupted:
				return "transport"
			case causeTLS:
				return "tls"
			case causeHTTPStatus:
				return "http_status"
			case causeInvalidResponse:
				return "invalid_response"
			}
		}
	}
	return "unknown"
}

var errProbeMismatch = errors.New("probe IP mismatch")

// freeze closes in-flight spans before Go's detached HTTP dial callbacks unwind.
// Every caller gets a deep copy; late callbacks cannot change persisted records.
func (t *probeTrace) freeze(e error) probeRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.frozen {
		t.frozen = true
		t.record.ElapsedMS = time.Since(t.start).Milliseconds()
		t.record.Outcome, t.record.Stage, t.record.Cause = "success", "verify", probeCause(e)
		if e != nil {
			t.record.Outcome = "failure"
		}
		for i := range t.record.Stages {
			span := &t.record.Stages[i]
			t.record.Stage, t.record.Scope = span.Stage, span.Scope
			if !span.ended {
				span.ElapsedMS, span.Outcome, span.Cause = time.Since(span.start).Milliseconds(), t.record.Outcome, t.record.Cause
			}
		}
		if e != nil {
			p := safeProbeError(e)
			if p.kind == probeHTTPStatus {
				t.record.HTTPStatus = p.status
			}
			if p.forward != nil {
				t.record.HTTPStatus = p.forward.status
			}
		}
	}
	r := t.record
	r.Stages = append([]probeSpan(nil), r.Stages...)
	return r
}

type probeHTTPTrace struct {
	mu                sync.Mutex
	tlsDone, httpDone func(error)
}

func traceProbeHTTP(ctx context.Context, dns bool, ready *atomic.Bool) (context.Context, *probeHTTPTrace) {
	t := &probeHTTPTrace{}
	if traceFrom(ctx) == nil {
		return ctx, t
	}
	ctx = context.WithValue(ctx, probeScopeKey{}, dns)
	tlsStage, httpStage := diagnosticTargetTLS, diagnosticTargetHTTP
	if dns {
		tlsStage, httpStage = diagnosticDNSTLS, diagnosticDNSHTTP
	}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			if ready.Load() {
				t.mu.Lock()
				t.tlsDone = beginProbeStage(ctx, tlsStage)
				t.mu.Unlock()
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
			if ready.Load() {
				t.mu.Lock()
				if t.tlsDone != nil {
					t.tlsDone(e)
				}
				t.mu.Unlock()
			}
		},
		GotConn: func(httptrace.GotConnInfo) {
			if ready.Load() {
				t.mu.Lock()
				t.httpDone = beginProbeStage(ctx, httpStage)
				t.mu.Unlock()
			}
		},
	})
	return ctx, t
}
func (t *probeHTTPTrace) headersDone(e error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.httpDone != nil {
		t.httpDone(e)
	}
}

func (s *Service) startProbeTrace(ctx context.Context, op probeOperation, generation uint64, attempt int, parent string) context.Context {
	now := time.Now()
	t := &probeTrace{start: now, record: probeRecord{Version: 1, Event: "probe", Time: now.UTC().Format(time.RFC3339Nano), ProcessID: s.diagnostics.processID, CheckID: diagnosticID(), ParentCheckID: parent, Operation: op.String(), Generation: generation, Attempt: attempt}}
	if deadline, ok := ctx.Deadline(); ok {
		t.record.BudgetMS = max(0, deadline.Sub(now).Milliseconds())
	}
	s.mu.Lock()
	t.record.ActiveConnections = len(s.connections)
	if op == diagnosticHealth {
		if !s.lastHealthStart.IsZero() {
			t.record.HealthGapMS = now.Sub(s.lastHealthStart).Milliseconds()
		}
		s.lastHealthStart = now
	}
	s.mu.Unlock()
	return context.WithValue(ctx, probeTraceKey{}, t)
}
func (s *Service) finishProbeTrace(ctx context.Context, failure error) {
	t := traceFrom(ctx)
	if t == nil {
		return
	}
	t.mu.Lock()
	frozen := t.frozen
	t.mu.Unlock()
	if !frozen && ctx.Err() != nil {
		failure = ctx.Err()
	}
	s.diagnostics.write(t.freeze(failure))
}
func probeTraceSuffix(ctx context.Context, e error) string {
	t := traceFrom(ctx)
	if t == nil {
		return ""
	}
	r := t.freeze(e)
	return fmt.Sprintf(" [check=%s stage=%s elapsed=%dms]", r.CheckID, r.Stage, r.ElapsedMS)
}
