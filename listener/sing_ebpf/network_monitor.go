//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"github.com/metacubex/mihomo/log"

	list "github.com/metacubex/sing/common/x/list"

	tun "github.com/metacubex/sing-tun"
)

// localNetworkMonitor keeps the local cgroup policy in step with the machine's
// interfaces.
//
// The shared TC manager already has a monitor, but it owns and closes it, and
// the two paths are enabled independently: local mode on its own still has to
// learn about address changes, because its host-address policy is compiled from
// the current interface addresses. Without this the policy stayed at whatever
// the machine looked like when the inbound started -- and since listeners start
// before the TUN device is created, that snapshot never contained the TUN
// address at all.
//
// Monitoring is best effort. A kernel or vendor policy that refuses the netlink
// subscription (Android 14+ restricts it) must not stop the inbound from
// attaching; the policy then simply keeps its startup value, which is the
// behaviour that existed before.
type localNetworkMonitor struct {
	monitor  tun.NetworkUpdateMonitor
	callback *list.Element[tun.NetworkUpdateCallback]
}

func (i *Inbound) startLocalNetworkMonitor() {
	monitor, err := tun.NewNetworkUpdateMonitor(log.SingLogger)
	if err != nil {
		log.Debugln("[EBPF] local interface monitor unavailable, host addresses keep their startup value: %s", err.Error())
		return
	}
	if err = monitor.Start(); err != nil {
		_ = monitor.Close()
		log.Debugln("[EBPF] start local interface monitor, host addresses keep their startup value: %s", err.Error())
		return
	}
	i.localNetwork = &localNetworkMonitor{
		monitor:  monitor,
		callback: monitor.RegisterCallback(i.InterfaceUpdated),
	}
}

func (i *Inbound) stopLocalNetworkMonitor() {
	local := i.localNetwork
	if local == nil {
		return
	}
	i.localNetwork = nil
	if local.callback != nil {
		local.monitor.UnregisterCallback(local.callback)
	}
	_ = local.monitor.Close()
}
