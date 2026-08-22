//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/log"
)

// reportKernelCapabilities logs the eBPF features this kernel cannot provide.
//
// Every one of these degradations is already handled -- the inbound falls back
// and keeps working -- which is exactly the problem: nothing said so. A kernel
// older than 5.5 has no cgroup/sock_release, so the self-bypass and connected-UDP
// entries are never deleted on close and only the LRU reclaims them; a kernel
// older than 5.14 cannot lookup-and-delete a hash map, so the redirect sweeper
// declines to run at all. Both look identical to a healthy setup from the
// outside until state pressure starts costing flows. ProbeKernel already knew
// all of this and had no callers.
//
// Runs on its own goroutine: the probe loads and unloads throwaway programs,
// and startup should not wait on that.
func reportKernelCapabilities(mode ECommon.KernelProbeMode, network []string, cgroupPath string, interfaceName string) {
	go func() {
		report, err := ECommon.ProbeKernel(ECommon.KernelProbeOptions{
			Mode:          mode,
			Network:       network,
			CgroupPath:    cgroupPath,
			InterfaceName: interfaceName,
		})
		if err != nil {
			log.Debugln("[EBPF] kernel capability probe skipped: %s", err)
			return
		}
		var degraded []string
		for _, finding := range report.Findings {
			if finding.Status == ECommon.KernelProbePass {
				continue
			}
			// A required failure would already have stopped the inbound from
			// starting, so anything left here is a working-but-reduced path.
			degraded = append(degraded, finding.Scope+"/"+finding.Feature+": "+finding.Detail)
		}
		if len(degraded) == 0 {
			log.Debugln("[EBPF] kernel %s provides every probed capability", report.KernelRelease)
			return
		}
		// Do not summarise what the shortfall costs: the findings differ in kind.
		// A missing inet_sock_release slows reclamation, while a missing
		// bpf_get_current_pid_tgid changes how the inbound recognises its own
		// sockets. Each finding carries its own consequence; print those.
		log.Warnln("[EBPF] kernel %s lacks %d optional capability(ies); the inbound is running on the fallback path for each:\n  - %s",
			report.KernelRelease, len(degraded), strings.Join(degraded, "\n  - "))
	}()
}
