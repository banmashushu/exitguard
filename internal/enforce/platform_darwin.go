//go:build darwin

package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"time"
)

const managerPath = "/Applications/ExitGuard.app/Contents/MacOS/ExitGuardFilterManager"
const managerIdentifier = "com.exitguard.app"

// Set only by the signed-deployment build. An ordinary local/ad-hoc build must
// never trust arbitrary manager JSON as evidence of a working OS extension.
var signingTeamID string
var teamPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

func trustedManager(ctx context.Context) error {
	if !teamPattern.MatchString(signingTeamID) {
		return errors.New("signed Network Extension deployment is unavailable: build has no pinned Apple signing team")
	}
	info, err := os.Lstat(managerPath)
	if err != nil {
		return fmt.Errorf("signed filter manager is missing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Mode()&0022 != 0 {
		return errors.New("filter manager must be a regular executable without group/world write access")
	}
	requirement := `anchor apple generic and identifier "` + managerIdentifier + `" and certificate leaf[subject.OU] = "` + signingTeamID + `"`
	command := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R", requirement, "--", managerPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("filter manager signature does not match the pinned Apple signing team")
	}
	return nil
}

func Supported() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return trustedManager(ctx) == nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("filter manager response too large")
	}
	return b.Buffer.Write(p)
}

func runManager(ctx context.Context, operation string, p Policy) ([]byte, error) {
	deadline := 15 * time.Second
	if operation == "install" {
		deadline = 125 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if err := trustedManager(ctx); err != nil {
		return nil, err
	}
	input, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, managerPath, operation)
	command.Stdin = bytes.NewReader(input)
	output := &boundedBuffer{limit: 16384}
	command.Stdout = output
	command.Stderr = io.Discard
	if operation=="install" {command.Stderr=os.Stderr}
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("signed filter manager %s failed: %w", operation, err)
	}
	return output.Bytes(), nil
}

func inspect(ctx context.Context, p Policy) (Proof, error) {
	output, err := runManager(ctx, "inspect", p)
	if err != nil {
		return Proof{Reason: err.Error()}, err
	}
	return parseManagerProof(output, Hash(p))
}
func install(ctx context.Context, p Policy) error {
	output, err := runManager(ctx, "install", p)
	if err != nil {
		return err
	}
	_, err = parseManagerProof(output, Hash(p))
	return err
}
func remove(ctx context.Context, p Policy) error { _, err := runManager(ctx, "remove", p); return err }
