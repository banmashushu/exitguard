//go:build !darwin && (!windows || !amd64)

package enforce

import "context"

func Supported() bool { return false }
func inspect(context.Context, Policy) (Proof, error) {
	return Proof{Reason: ErrUnsupported.Error()}, ErrUnsupported
}
func install(context.Context, Policy) error { return ErrUnsupported }
func remove(context.Context, Policy) error  { return ErrUnsupported }
