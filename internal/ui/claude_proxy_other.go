//go:build !darwin

package ui

import "os/exec"

func prepareClaudeProxyCommand(*exec.Cmd, string) error { return nil }
