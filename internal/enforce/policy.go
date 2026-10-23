// Package enforce attests native OS enforcement. A successful IP probe is never
// a substitute for an Active proof for the exact current policy.
package enforce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Policy struct {
	Port      uint16   `json:"port"`
	Programs  []string `json:"programs"`
	BundleIDs []string `json:"bundleIDs"`
}

type Proof struct {
	Active     bool   `json:"active"`
	PolicyHash string `json:"policyHash"`
	Reason     string `json:"reason"`
}

var ErrUnsupported = errors.New("native process enforcement is unavailable")
var bundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$`)

func normalize(p Policy) (Policy, error) {
	if p.Port == 0 {
		return Policy{}, errors.New("guard proxy port must be nonzero")
	}
	if len(p.Programs)+len(p.BundleIDs) == 0 {
		return Policy{}, errors.New("at least one protected executable or application identity is required")
	}
	if len(p.Programs)+len(p.BundleIDs) > 256 {
		return Policy{}, errors.New("too many protected targets")
	}
	for _, path := range p.Programs {
		windowsAbsolute := len(path) > 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
		if len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") || (!strings.HasPrefix(path, "/") && !windowsAbsolute) {
			return Policy{}, errors.New("protected executable paths must be absolute and contain no control characters")
		}
	}
	for _, id := range p.BundleIDs {
		if len(id) > 255 || !bundleIDPattern.MatchString(id) {
			return Policy{}, errors.New("invalid protected application identifier")
		}
	}
	p.Programs = uniqueSorted(p.Programs)
	p.BundleIDs = uniqueSorted(p.BundleIDs)
	return p, nil
}

func uniqueSorted(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	result := out[:0]
	for _, v := range out {
		if len(result) == 0 || v != result[len(result)-1] {
			result = append(result, v)
		}
	}
	return result
}

// Hash binds the proxy port, case-sensitive executable paths and identities.
// Invalid policies have no hash and can never produce a positive proof.
func Hash(p Policy) string {
	p, err := normalize(p)
	if err != nil {
		return ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "ExitGuard.Policy.v1\n%d\n", p.Port)
	for _, value := range p.Programs {
		fmt.Fprintf(h, "p%d:%s\n", len(value), value)
	}
	for _, value := range p.BundleIDs {
		fmt.Fprintf(h, "b%d:%s\n", len(value), value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Inspect(ctx context.Context, p Policy) (Proof, error) {
	p, err := normalize(p)
	if err != nil {
		return Proof{Reason: err.Error()}, err
	}
	if err := ctx.Err(); err != nil {
		return Proof{Reason: err.Error()}, err
	}
	return inspect(ctx, p)
}

func Install(ctx context.Context, p Policy) error {
	p, err := normalize(p)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return install(ctx, p)
}

func Remove(ctx context.Context, p Policy) error {
	p, err := normalize(p)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return remove(ctx, p)
}
