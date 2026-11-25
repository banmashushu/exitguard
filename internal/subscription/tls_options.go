package subscription

import (
	"encoding/json"
	"strconv"
)

const nodeSkipCertVerify = "skip-cert-verify"

// Node TLS settings are data passed to Mihomo, not settings for the application
// transports used to download subscriptions or verify the final exit.
func nodeTLSBool(value any) (bool, bool) {
	switch value := value.(type) {
	case bool:
		return value, true
	case int:
		return value == 1, value == 0 || value == 1
	case int64:
		return value == 1, value == 0 || value == 1
	case uint64:
		return value == 1, value == 0 || value == 1
	case float64:
		return value == 1, value == 0 || value == 1
	case json.Number:
		return value == "1", value == "0" || value == "1"
	case string:
		flag, err := strconv.ParseBool(value)
		return flag, err == nil
	}
	return false, false
}

func nodeSkipsTLSVerification(value any, depth int) bool {
	if depth > 16 {
		return false
	}
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			key = nativeKey(key)
			if key == "headers" || key == "ws-headers" {
				continue
			}
			if key == nodeSkipCertVerify && item == true {
				return true
			}
			if nodeSkipsTLSVerification(item, depth+1) {
				return true
			}
		}
	case []any:
		for _, item := range value {
			if nodeSkipsTLSVerification(item, depth+1) {
				return true
			}
		}
	}
	return false
}
