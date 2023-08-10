package ebpf

import (
	gocontext "context"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"time"
)

func (t *Tracee) detectFtraceHooksRoutine(ctx gocontext.Context) {
	logger.Debugw("Starting detectFtraceHooksRoutine goroutine")
	defer logger.Debugw("Stopped detectFtraceHooksRoutine goroutine")

	if t.eventsState[events.FtraceHook].Emit == 0 {
		return
	}
	for {
		t.triggerFtraceHookChecker()
		time.Sleep(10 * time.Second)
	}

	//TODO
	//for {
	//	select {
	//	case <-time.After(generateRandomDuration(10, 300)):
	//		t.triggerFtraceHookChecker()
	//	case <-ctx.Done():
	//		return
	//	}
	//}
}

//go:noinline
func (t *Tracee) triggerFtraceHookChecker() {
}
