package ebpf

import (
	gocontext "context"
	"math/rand"
	"time"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/derive"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// lkmSeekerRoutine handles the kernel module hiding check logic.
// The logic runs periodically, unless getting interrupted by a message in the channel.
// Currently, there are 2 types of messages:
//  1. A new kernel module was loaded, trigger a check for hidden kernel modules.
//  2. Found hidden module by new mod logic (check newModsCheckForHidden for more info), submit it back to eBPF,
//     which will return it to userspace, this time making it get submitted as an event to the user.
//
// Since each module insert will cause the logic to run, we want to avoid exhausting the system (say someone loads modules in a loop).
// To address that, there's a cool-down period which must pass for the scan to rerun.
// Several techniques is used to find hidden modules - each of them is triggered by using a tailcall.
func (t *Tracee) lkmSeekerRoutine(ctx gocontext.Context) {
	logger.Debugw("Starting lkmSeekerRoutine goroutine")
	defer logger.Debugw("Stopped lkmSeekerRoutine goroutine")

	if t.events[events.HiddenKernelModule].emit == 0 {
		return
	}

	modsMap, err := t.bpfModule.GetMap("modules_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	newModMap, err := t.bpfModule.GetMap("new_module_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	deletedModMap, err := t.bpfModule.GetMap("recent_deleted_module_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	insertedModMap, err := t.bpfModule.GetMap("recent_inserted_module_map")
	if err != nil {
		logger.Errorw("Error occurred GetMap: " + err.Error())
		return
	}

	err = derive.InitHiddenKernelModules(modsMap, newModMap, deletedModMap, insertedModMap)
	if err != nil {
		return
	}

	wakeupChan := derive.GetWakeupChannelRead()

	// generateRandomDuration returns a random duration between min and max, inclusive
	generateRandomDuration := func(min, max int) time.Duration {
		randDuration := time.Duration(rand.Intn(max-min+1)+min) * time.Second
		return randDuration
	}

	// Since on each module load the scan is triggered, the following variables are used to enforce that we scan
	// at most once in minSleepBetweenRuns seconds, to avoid exhausting the system
	lastTriggerTime := time.Now()
	var minSleepTimer <-chan time.Time
	const minSleepBetweenRuns = 2 // Seconds

	// Marks when the lkm hiding whole seeking logic should run.
	run := true

	for {
		if run {
			if minSleepTimer != nil {
				run = false
				continue // A run is scheduled in the future, so don't run yet
			}

			if lastTriggerTime.Add(minSleepBetweenRuns * time.Second).After(time.Now()) { // minSleepBetweenRuns seconds had yet passed since our last run, sleep the remaining time and run afterwards
				minSleepTimer = time.After(time.Until(lastTriggerTime.Add(minSleepBetweenRuns * time.Second)))
				run = false
				continue
			}

			err = derive.FillModulesFromProcFs(t.kernelSymbols)
			if err != nil {
				logger.Errorw("Hidden kernel module seeker stopped!: " + err.Error())
				return
			}
			lastTriggerTime = time.Now()

			t.triggerKernelModuleSeeker()

			derive.ClearModulesState()
		}

		select {
		case <-time.After(generateRandomDuration(10, 300)): // Random time to sleep between each run
			run = true
		case scanReq := <-wakeupChan: // Wake up by a message in the channel
			if scanReq.Flags&derive.FullScan != 0 {
				run = true
			} else if scanReq.Flags&derive.NewMod != 0 { // Send to the submitter
				run = false
				t.triggerKernelModuleSubmitter(scanReq.Address, uint64(scanReq.Flags))
			} else {
				logger.Errorw("lkm_seeker: unexpected flags", "flags", scanReq.Flags)
			}
		case <-minSleepTimer: // Cool-down period ended - run now
			minSleepTimer = nil
			run = true
		case <-ctx.Done():
			return
		}
	}
}

//go:noinline
func (t *Tracee) triggerKernelModuleSeeker() {
}

//go:noinline
func (t *Tracee) triggerKernelModuleSubmitter(address uint64, flags uint64) {
}
