package subscription

import (
	"errors"
	"strings"
)

var ErrEmptyResponse = errors.New("订阅服务器返回空内容；请核对订阅下载设置后重试")
var ErrClientDenied = errors.New("订阅服务拒绝当前客户端；请核对该订阅允许的客户端与下载设置")

// ResponseFailure returns only fixed, known categories. A wrapped source error
// may contain a URL or server text, so callers must not display source.Error().
func ResponseFailure(source error) error {
	for _, known := range []error{ErrEmptyResponse, ErrClientDenied, ErrContent, ErrActiveRouteUnavailable, ErrNativeConversion} {
		if errors.Is(source, known) {
			return known
		}
	}
	return nil
}

func sourceResponseFailure(content []byte) error {
	text := strings.TrimSpace(strings.TrimPrefix(string(content), "\ufeff"))
	if text == "" {
		return ErrEmptyResponse
	}
	if text == "This client is not allowed to fetch subscription" {
		return ErrClientDenied
	}
	return nil
}
