package net

import (
	"net"
	"sync/atomic"
)

// tcpSpliceHook is an optional kernel relay for an already-routed DIRECT TCP
// connection pair. It is registered by the eBPF inbound (the experimental
// tcp-splice feature) and follows the same process-wide hook pattern as
// dialer.RegisterSocketProtectFunc. When the hook returns true, both
// connection endpoints are transferred to the hook, which becomes responsible
// for closing them once the pair ends; returning false keeps the pair owned by
// the userspace relay.
var tcpSpliceHook atomic.Value // *func(local, remote net.Conn) bool

// RegisterTCPSplicer installs (or, with nil, removes) the kernel TCP splice
// hook consulted before the tunnel starts relaying a DIRECT connection.
func RegisterTCPSplicer(hook func(local, remote net.Conn) bool) {
	if hook == nil {
		tcpSpliceHook.Store((*func(local, remote net.Conn) bool)(nil))
		return
	}
	tcpSpliceHook.Store(&hook)
}

// LoadTCPSplicer returns the registered splice hook, or nil.
func LoadTCPSplicer() func(local, remote net.Conn) bool {
	if value := tcpSpliceHook.Load(); value != nil {
		if hook, ok := value.(*func(local, remote net.Conn) bool); ok && hook != nil {
			return *hook
		}
	}
	return nil
}
