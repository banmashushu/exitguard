package guard

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

type failureStage uint8

const (
	stageProxyTLS failureStage = iota
	stageSOCKSHandshake
	stageHTTPHandshake
	stageDNS
)

type failureCause uint8

const (
	causeUnknown failureCause = iota
	causeTimeout
	causeInterrupted
	causeTLS
	causeCancelled
	causeHTTPStatus
	causeInvalidResponse
)

// forwardError retains only fixed classifications, never the source error or
// target/account data. local is set only after DoH GotConn verifies its tunnel
// and TLS connection; it never makes a public-IP probe request-local.
type forwardError struct {
	stage  failureStage
	cause  failureCause
	status int
	local  bool
}

func (e *forwardError) Error() string {
	stage := "指定出口连接"
	switch e.stage {
	case stageProxyTLS:
		stage = "HTTPS 代理 TLS 连接"
	case stageSOCKSHandshake:
		stage = "SOCKS5 代理握手"
	case stageHTTPHandshake:
		stage = "HTTP 代理握手"
	case stageDNS:
		stage = "安全 DNS"
	}
	switch e.cause {
	case causeTimeout:
		return stage + "超时"
	case causeInterrupted:
		return stage + "传输中断"
	case causeTLS:
		return stage + "证书或 TLS 协议验证失败"
	case causeCancelled:
		return stage + "已取消"
	case causeHTTPStatus:
		return fmt.Sprintf("%s收到 HTTP %d", stage, e.status)
	case causeInvalidResponse:
		return stage + "返回无效响应"
	default:
		return stage + "失败（未识别的错误）"
	}
}

func (e *forwardError) transient() bool {
	return e.cause == causeTimeout || e.cause == causeInterrupted || e.stage == stageDNS && e.cause == causeHTTPStatus && (e.status == 429 || e.status >= 500 && e.status <= 599)
}

func (e *forwardError) requestLocal() bool {
	return e.stage == stageDNS && e.local && e.transient()
}

func (e *forwardError) httpStatus() int {
	if e.cause == causeTimeout {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func transportFailure(stage failureStage, source error, allowTruncatedBody bool) *forwardError {
	failure := &forwardError{stage: stage}
	switch safeProbeError(source).kind {
	case probeTimeout:
		failure.cause = causeTimeout
	case probeCancelled:
		failure.cause = causeCancelled
	case probeNetworkFailure:
		failure.cause = causeInterrupted
	case probeTLSFailure, probeTLSProtocolFailure:
		failure.cause = causeTLS
	default:
		if errors.Is(source, io.EOF) || allowTruncatedBody && errors.Is(source, io.ErrUnexpectedEOF) {
			failure.cause = causeInterrupted
		}
	}
	return failure
}

// A DoH dial failure happened before a usable resolver connection exists. Keep
// known upstream failures and target refusals; sanitize all other dial errors
// here so they cannot later masquerade as an ordinary DNS exchange failure.
func dnsDialFailure(source error) error {
	var upstream *upstreamError
	var destination *destinationError
	var known *forwardError
	if errors.As(source, &upstream) || errors.As(source, &destination) || errors.As(source, &known) {
		return source
	}
	// An unclassified socket error may be a binding/control failure, not a
	// network outage. Remote routes already classify their transport failures.
	return &forwardError{stage: stageDNS, cause: causeUnknown}
}
