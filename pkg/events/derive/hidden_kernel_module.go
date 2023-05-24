package derive

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	foundHiddenKernModsCache *lru.Cache
	allModsMap               *bpf.BPFMap
	newModuleOnlyMap         *bpf.BPFMap
	recentDeletedModulesMap  *bpf.BPFMap
	recentInsertedModulesMap *bpf.BPFMap
	wakeupChannel            = make(chan ScanRequest)
)

const (
	ProcModules  uint32 = 1 << 0  // A hidden module detected by /proc/modules logic
	kset                = 1 << 1  // A hidden module detected by kset logic
	modTree             = 1 << 2  // A hidden module detected by mod tree logic
	NewMod              = 1 << 3  // A new modules only scan - without HiddenModule flag on, this is not yet a detection. See newModsCheckForHidden
	FullScan            = 1 << 30 // Do a full scan - received after a new module was loaded (and finished running his init function)
	HiddenModule        = 1 << 31 // Submit the module as event to user
)

// ScanRequest the structure that is passed in the wake up channel
type ScanRequest struct {
	Address uint64
	Flags   uint32
}

func HiddenKernelModule() DeriveFunction {
	return deriveSingleEvent(events.HiddenKernelModule, deriveHiddenKernelModulesArgs())
}

func deriveHiddenKernelModulesArgs() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		address, err := parse.ArgVal[uint64](&event, "address")
		if err != nil {
			return nil, err
		}

		if _, found := foundHiddenKernModsCache.Get(address); found {
			return nil, nil // Already reported this event - no need to report again
		}

		flags, err := parse.ArgVal[uint32](&event, "flags")
		if err != nil {
			return nil, err
		}

		// revive:disable // revive complains about empty if block... but it's needed to avoid entering other blocks, if that flag is on.
		if flags&HiddenModule != 0 {
			// Continue submit an event to user
		} else if flags&FullScan != 0 {
			wakeupChannel <- ScanRequest{Flags: flags} // No need to send the address as we're doing a full generic scan
			return nil, nil
		} else if flags&NewMod != 0 {
			startScanTime := address // The address field in this case is unused, so it's being utilized as the start scan time
			err := newModsCheckForHidden(startScanTime, flags)
			return nil, err
		}
		// revive:enable

		var name string
		nameBytes, err := parse.ArgVal[[]byte](&event, "name")
		if err != nil {
			name = ""
			logger.Debugw("Failed extracting hidden module name") // Don't fail hard - submit it without a name!
		} else {
			name = string(nameBytes[:bytes.IndexByte(nameBytes[:], 0)]) // Remove the trailing terminating characters
		}

		var srcversion string
		srcversionBytes, err := parse.ArgVal[[]byte](&event, "srcversion")
		if err != nil {
			srcversion = ""
			logger.Debugw("Failed extracting hidden module srcversion") // Don't fail hard - submit it without a srcversion!
		} else {
			srcversion = string(srcversionBytes[:bytes.IndexByte(srcversionBytes[:], 0)]) // Remove the trailing terminating characters
		}

		addrHex := fmt.Sprintf("0x%x", address)
		if len(addrHex) == 2 {
			logger.Warnw("Failed converting module address to hex")
		}

		foundHiddenKernModsCache.Add(address, struct{}{}) // So we won't report multiple times

		return []interface{}{addrHex, name, srcversion}, nil
	}
}

// newModsCheckForHidden monitors only new added modules (added while tracee is running),
// and reports if they are hidden
func newModsCheckForHidden(startScanTime uint64, flags uint32) error {
	// Since in old kernels it is not possible to iterate on a hashmap, the job is done here (userspace).
	// It goes over a map that is maintained in the eBPF code (on each module insertion/deletion the map is updated),
	// and checks if each module was seen (in modules list), and when was it inserted (to address race conditions).
	// Based on this information, it determines whether it's hidden or not.
	// If found hidden, it sends a message in the channel, which causes the address and the flags to get passed
	// to the lkm submitter program (eBPF), which sends it back to userspace,
	// this time with flags that will cause it to get submitted to the user as an event,
	err := capabilities.GetInstance().Specific(
		func() error {
			var iter = newModuleOnlyMap.Iterator()
			for iter.Next() {
				addr := binary.LittleEndian.Uint64(iter.Key())
				curVal, err := newModuleOnlyMap.GetValue(unsafe.Pointer(&addr))
				if err != nil {
					return err
				}
				insertTime := binary.LittleEndian.Uint64(curVal[0:8])
				lastSeenTime := binary.LittleEndian.Uint64(curVal[8:16])
				if insertTime <= startScanTime && lastSeenTime < startScanTime {
					// It was inserted before the current scan, and we did not see it in the scan - it's hidden
					// The receiving end will receive the message, trigger the lkm seeker submitter with a specific hidden module
					// Note that we haven't really checked if the module is in the cache before,
					// as we only have the address now.
					if _, found := foundHiddenKernModsCache.Get(addr); !found {
						wakeupChannel <- ScanRequest{Address: addr, Flags: flags} // It's hidden - and we haven't reported it before - report.
					}
				}
			}

			err := iter.Err()
			if err != nil {
				logger.Errorw("clearMap iterator received an error", "error", err.Error())
				return iter.Err()
			}

			return nil
		},
		cap.SYS_ADMIN,
	)

	return err
}

// InitHiddenKernelModules initializes the module components
func InitHiddenKernelModules(modsMap *bpf.BPFMap, newModMap *bpf.BPFMap, deletedModMap *bpf.BPFMap, insertedModMap *bpf.BPFMap) error {
	allModsMap = modsMap
	newModuleOnlyMap = newModMap
	recentDeletedModulesMap = deletedModMap
	recentInsertedModulesMap = insertedModMap

	var err error
	foundHiddenKernModsCache, err = lru.New(2048)
	if err != nil {
		logger.Errorw("Error occurred initializing kernel hidden modules: " + err.Error())
	}
	return err
}

// clearMap a utility to clear a map
func clearMap(bpfMap *bpf.BPFMap) error {
	err := capabilities.GetInstance().Specific(
		func() error {
			var err error
			var iter = bpfMap.Iterator()
			for iter.Next() {
				addr := binary.LittleEndian.Uint64(iter.Key())
				err = bpfMap.DeleteKey(unsafe.Pointer(&addr))

				if err != nil {
					logger.Errorw("Err occurred DeleteKey: " + err.Error())
					return err
				}
			}
			err = iter.Err()
			if err != nil {
				logger.Errorw("ClearMap iterator received an error", "error", err.Error())
				return iter.Err()
			}

			return nil
		},
		cap.SYS_ADMIN, // Required for (older) kernels that require CAP_SYS_ADMIN to interact with eBPF maps
	)

	return err
}

// GetWakeupChannelRead returns the reading-end of the channel
func GetWakeupChannelRead() <-chan ScanRequest {
	return wakeupChannel
}

// ClearModulesState clears the map
func ClearModulesState() {
	_ = clearMap(allModsMap)
	_ = clearMap(recentDeletedModulesMap)  // We only care for modules that got deleted in the midst of a scan (and since we're not scanning now, clear the map)
	_ = clearMap(recentInsertedModulesMap) // We only care for modules that got inserted in the midst of a scan (and since we're not scanning now, clear the map)
}

// FillModulesFromProcFs fills a map with modules from /proc/modules, to be checked in kernel-space for inconsistencies.
func FillModulesFromProcFs(kernelSymbols helpers.KernelSymbolTable) error {
	err := capabilities.GetInstance().Specific(
		func() error {
			file, err := os.Open("/proc/modules")
			if err != nil {
				logger.Errorw("Error opening /proc/modules", err)
				return errors.New("error opening /proc/modules")
			}
			defer func() {
				if err := file.Close(); err != nil {
					logger.Errorw("Error closing /proc/modules", err)
				}
			}()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				lineSplit := strings.Split(line, " ")
				lineLen := len(lineSplit)
				if lineLen < 3 {
					logger.Warnw("Unexpected format in /proc/modules", lineSplit)
					return errors.New("unexpected format in /proc/modules")
				}

				moduleName := lineSplit[0]
				var addr uint64

				// get module address from kallsyms since /proc/modules doesn't return the address to __this_module
				ks, err := kernelSymbols.GetSymbolByName(moduleName, "__this_module")
				if err != nil {
					// this most likely means /proc/kallsyms is hooked while /proc/modules isn't
					// fallback to use the address in /proc/modules
					candOne := lineSplit[len(lineSplit)-1]
					candTwo := lineSplit[len(lineSplit)-2]
					var finalCand string
					if strings.HasPrefix(candOne, "0x") {
						finalCand = candOne[2:]
					} else {
						finalCand = candTwo[2:]
					}

					result, parseErr := strconv.ParseUint(finalCand, 16, 64)
					if parseErr == nil {
						addr = result
					}
				} else {
					addr = ks.Address
				}
				seenInProcModules := true
				err = allModsMap.Update(unsafe.Pointer(&addr), unsafe.Pointer(&seenInProcModules))
				if err != nil {
					logger.Errorw("Failed updating allModsMap", err)
					return errors.New("failed updating allModsMap")
				}
			}

			if err := scanner.Err(); err != nil {
				logger.Errorw("scanner reported error: ", err)
			}

			return nil
		},
		cap.SYS_ADMIN, // Need capability to update the eBPF map
	)
	return err
}
