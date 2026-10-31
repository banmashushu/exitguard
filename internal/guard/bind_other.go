//go:build !darwin

package guard

import (
	"errors"
	"exitguard/internal/model"
)

func newBoundRoute(model.Config) (route, error) {
	return nil, errors.New("当前平台不支持飞连接口绑定路径")
}
