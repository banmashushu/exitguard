//go:build !windows || !amd64

package nativeapp

import (
	"context"
	"errors"
	"os/exec"
)

func unavailable() error {
	return errors.New("原生应用预览需要 Windows x64 和单独安装的官方 Sandboxie Plus v1.18.8；当前系统仅可生成预览配置")
}
func inspect(context.Context) (Inspection, error) {
	return Inspection{State: "unavailable", Reason: unavailable().Error()}, unavailable()
}
func prepare(context.Context, string, string) (*exec.Cmd, error) { return nil, unavailable() }
func apply(context.Context, string) error                        { return unavailable() }
func stage(context.Context) (string, []byte, error)              { return "", Snippet(), unavailable() }
func Membership(context.Context, uint32) (string, uint64, error) { return "", 0, unavailable() }
func probeCommand(context.Context, string) (*exec.Cmd, error)    { return nil, unavailable() }
func requireUnboxed(context.Context) error                       { return unavailable() }

func targetsStopped() error { return unavailable() }
