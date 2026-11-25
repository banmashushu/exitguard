//go:build !darwin

package ui

import (
	"context"
	"errors"
)

func RemoveClaudeProxy(context.Context) (bool, error) {
	return false, errors.New("此入口适用于 macOS")
}

func LaunchChromeWithoutProxy(context.Context, string) error {
	return errors.New("此入口适用于 macOS")
}
