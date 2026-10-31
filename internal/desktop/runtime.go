package desktop

import (
	"context"
	"errors"
	"time"
)

type runningCore interface {
	Run(context.Context) error
	WaitReady(context.Context) error
	Disarm()
}

// ServiceRuntime owns the in-process guard lifetime. No HTTP control handler is
// installed; its one listener accepts only the already guarded proxy traffic.
type ServiceRuntime struct {
	core   runningCore
	cancel context.CancelFunc
	done   chan struct{}
	err    error // written before done closes; read only after done
}

func StartService(ctx context.Context, core runningCore) (*ServiceRuntime, error) {
	ctx, cancel := context.WithCancel(ctx)
	r := &ServiceRuntime{core: core, cancel: cancel, done: make(chan struct{})}
	go func() {
		r.err = core.Run(ctx)
		close(r.done)
	}()
	ready, stopReady := context.WithTimeout(ctx, 5*time.Second)
	defer stopReady()
	if err := core.WaitReady(ready); err != nil {
		r.Close(3 * time.Second)
		return nil, errors.New("本地守护端口无法独占监听；请关闭冲突程序后重新打开 ExitGuard")
	}
	return r, nil
}

func (r *ServiceRuntime) Done() <-chan struct{} { return r.done }

func (r *ServiceRuntime) Err() error {
	select {
	case <-r.done:
		return r.err
	default:
		return nil
	}
}

// Close revokes forwarding before waiting boundedly for the listener to stop.
// It is also safe when a prior startup/quit path already canceled this runtime.
func (r *ServiceRuntime) Close(timeout time.Duration) bool {
	r.cancel()
	r.core.Disarm()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-r.done:
		return true
	case <-timer.C:
		return false
	}
}
