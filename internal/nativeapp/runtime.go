package nativeapp

import (
	"context"
	"os/exec"

	"exitguard/internal/enforce"
)

type SignatureEvidence struct {
	File       string `json:"file"`
	Valid      bool   `json:"valid"`
	Publisher  string `json:"publisher"`
	Thumbprint string `json:"thumbprint"`
	Version    string `json:"version"`
	Product    string `json:"product"`
}
type signatureError struct {
	Evidence SignatureEvidence
	Reason   string
}

func (e *signatureError) Error() string { return e.Reason }

type Inspection struct {
	Signatures     []SignatureEvidence       `json:"signatures,omitempty"`
	State          string                    `json:"state"`
	Reason         string                    `json:"reason"`
	RuntimeVersion string                    `json:"runtimeVersion,omitempty"`
	Filters        []enforce.SandboxieFilter `json:"filters,omitempty"`
	Boxes          []string                  `json:"boxes,omitempty"`
}

// Inspect never grants full protection, even after all preview prerequisites
// are present. DNS broker behavior and Windows application acceptance remain open.
func Inspect(ctx context.Context) (Inspection, error) { return inspect(ctx) }
func Prepare(ctx context.Context, target, path string) (*exec.Cmd, error) {
	return prepare(ctx, target, path)
}
func Apply(ctx context.Context, expectedHash string) error { return apply(ctx, expectedHash) }
func Stage(ctx context.Context) (string, []byte, error)    { return stage(ctx) }

// ProbeCommand only constructs the shipped probe invocation inside an owned
// box; it cannot accept an arbitrary executable or additional target arguments.
func ProbeCommand(ctx context.Context, target string) (*exec.Cmd, error) {
	return probeCommand(ctx, target)
}

func RequireUnboxed(ctx context.Context) error { return requireUnboxed(ctx) }

func RequireTargetsStopped() error { return targetsStopped() }
