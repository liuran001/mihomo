//go:build with_ebpf && !ebpf_debug && (linux || android)

package ebpf

import CiliumEBPF "github.com/cilium/ebpf"

func AcquireProgramRuntimeStats() (func() error, error) {
	return nil, nil
}

func populateProgramRuntimeStats(program *CiliumEBPF.Program, status *RuntimeProgramStatus) {
}
