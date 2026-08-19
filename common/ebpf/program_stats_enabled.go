//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"io"
	"sync"
	"sync/atomic"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var programRuntimeStatsState struct {
	access sync.Mutex
	closer io.Closer
	users  uint64
}

func AcquireProgramRuntimeStats() (func() error, error) {
	programRuntimeStatsState.access.Lock()
	defer programRuntimeStatsState.access.Unlock()
	if programRuntimeStatsState.users == 0 {
		closer, err := CiliumEBPF.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		if err != nil {
			return nil, err
		}
		programRuntimeStatsState.closer = closer
	}
	programRuntimeStatsState.users++
	var released atomic.Bool
	return func() error {
		if !released.CompareAndSwap(false, true) {
			return nil
		}
		programRuntimeStatsState.access.Lock()
		defer programRuntimeStatsState.access.Unlock()
		if programRuntimeStatsState.users == 0 {
			return nil
		}
		programRuntimeStatsState.users--
		if programRuntimeStatsState.users != 0 {
			return nil
		}
		closer := programRuntimeStatsState.closer
		programRuntimeStatsState.closer = nil
		if closer == nil {
			return nil
		}
		return closer.Close()
	}, nil
}

func populateProgramRuntimeStats(program *CiliumEBPF.Program, status *RuntimeProgramStatus) {
	stats, err := program.Stats()
	if err != nil {
		status.StatsError = err.Error()
		return
	}
	status.StatsKnown = true
	status.RunCount = stats.RunCount
	status.RuntimeNanos = uint64(max(stats.Runtime.Nanoseconds(), 0))
	status.RecursionMisses = stats.RecursionMisses
	if stats.RunCount != 0 {
		status.AverageNanos = status.RuntimeNanos / stats.RunCount
	}
}
