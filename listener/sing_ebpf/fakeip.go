//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

// The fake-ip ranges have to reach the kernel policy, not just the tunnel: a
// fake address carries no routable meaning, so it must be intercepted even when
// the destination would otherwise be bypassed. mihomo maps it back to its
// domain only once the flow reaches the tunnel, so a bypassed fake address is a
// dead end.
//
// This matters whenever the configured range sits inside a range the program
// bypasses. `fake-ip-range: 100.64.0.0/10` is inside the private set that
// bypass_private_address covers by default, so without this the whole fake-ip
// pool was handed straight past the redirect.
func (i *Inbound) startFakeIPTracking() {
	i.fakeIPRangeRemove = resolver.RegisterFakeIPRangeObserver(i.updateFakeIPRanges)
	// Register first, then read: a change published between the two is applied
	// twice rather than lost.
	i.updateFakeIPRanges(resolver.FakeIPRanges())
}

func (i *Inbound) stopFakeIPTracking() {
	if i.fakeIPRangeRemove == nil {
		return
	}
	i.fakeIPRangeRemove()
	i.fakeIPRangeRemove = nil
}

func (i *Inbound) updateFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) {
	if backend := i.backendInstance(); backend != nil {
		changed, err := backend.SetFakeIPRanges(ipv4, ipv6)
		switch {
		case err != nil:
			log.Warnln("[EBPF] update local cgroup fake-ip ranges: %s", err.Error())
		case changed:
			log.Infoln("[EBPF] local cgroup fake-ip ranges: ipv4=%s, ipv6=%s",
				fakeIPRangeText(ipv4), fakeIPRangeText(ipv6))
		}
	}
	if i.sharedNetwork == nil {
		return
	}
	shared := i.sharedNetwork.sharedBackendInstance()
	if shared == nil || shared.IsClosed() {
		return
	}
	changed, err := shared.SetFakeIPRanges(ipv4, ipv6)
	switch {
	case err != nil:
		log.Warnln("[EBPF] update shared-network fake-ip ranges: %s", err.Error())
	case changed:
		log.Infoln("[EBPF] shared-network fake-ip ranges: ipv4=%s, ipv6=%s",
			fakeIPRangeText(ipv4), fakeIPRangeText(ipv6))
	}
}

func fakeIPRangeText(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return "off"
	}
	return prefix.String()
}
