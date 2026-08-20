//go:build with_ebpf && !ebpf_debug && (linux || android)

package ebpf

const collectRuntimeMapEntries = false
