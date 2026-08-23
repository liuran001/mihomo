package sing_tun

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"

	"go4.org/netipx"
)

// ebpfRouteExcludeAddress returns the extra route-exclude prefixes a running
// eBPF inbound needs.
//
// The eBPF inbound bypasses a destination at the socket layer, which only means
// the socket keeps its original destination. The packet still follows the
// routing table, and auto-route points that table at this device, so without
// these exclusions every bypassed destination lands in TUN anyway and is routed
// by the rules -- a black hole for any destination the rules hand to a proxy
// that cannot reach it. Keeping the prefixes off the routes is what makes the
// bypass an actual direct connection.
//
// Only what the eBPF inbound published is excluded, so a config that carries an
// eBPF listener the kernel then refused to load does not silently change how
// TUN routes traffic.
func ebpfRouteExcludeAddress(tunAddressSets ...[]netip.Prefix) []netip.Prefix {
	published := resolver.EBPFRouteExcludePrefixes.Load()
	if published == nil || len(*published) == 0 {
		return nil
	}
	var builder netipx.IPSetBuilder
	for _, prefix := range *published {
		builder.AddPrefix(prefix)
	}
	// A fake-ip range that lands inside a bypassed range stays on the routes: a
	// fake address means nothing to the kernel, and the eBPF program forces
	// interception for it instead of bypassing it.
	fakeIPv4, fakeIPv6 := resolver.FakeIPRanges()
	removePrefix(&builder, fakeIPv4, fakeIPv6)
	// The device also has to keep reaching its own addresses.
	for _, prefixes := range tunAddressSets {
		removePrefix(&builder, prefixes...)
	}
	excluded, err := builder.IPSet()
	if err != nil || excluded == nil {
		return nil
	}
	return excluded.Prefixes()
}

func removePrefix(builder *netipx.IPSetBuilder, prefixes ...netip.Prefix) {
	for _, prefix := range prefixes {
		// An invalid prefix would be recorded as a builder error and discard the
		// whole set, so unset optional ranges have to be skipped here.
		if prefix.IsValid() {
			builder.RemovePrefix(prefix)
		}
	}
}

// publishTunRouteClaim records which destinations this listener took over, so
// the eBPF inbound can report the bypassed prefixes that will not be direct
// after all. The claim is the final route set, after every route-exclude option
// has been applied.
func publishTunRouteClaim(tunOptions *tun.Options) {
	if !tunOptions.AutoRoute {
		resolver.TunRouteClaimed.Store(nil)
		return
	}
	routeRanges, err := tunOptions.BuildAutoRouteRanges(false)
	if err != nil || len(routeRanges) == 0 {
		resolver.TunRouteClaimed.Store(nil)
		return
	}
	var builder netipx.IPSetBuilder
	for _, prefix := range routeRanges {
		builder.AddPrefix(prefix)
	}
	claimed, err := builder.IPSet()
	if err != nil {
		resolver.TunRouteClaimed.Store(nil)
		return
	}
	resolver.TunRouteClaimed.Store(&resolver.TunRouteClaim{Claimed: claimed})
	// The eBPF inbound starts before this listener, so it cannot see the claim
	// when it publishes its own policy. Report from this side too, otherwise an
	// overlap that never changes again is never reported at all.
	overlap := resolver.TunClaimedBypassPrefixes()
	if len(overlap) == 0 {
		return
	}
	tunDirect := false
	if policy := resolver.EBPFBypassPolicyValue.Load(); policy != nil {
		tunDirect = policy.TunDirect
	}
	message := resolver.TunBypassOverlapMessage(overlap, tunDirect)
	if tunDirect {
		log.Infoln("[TUN] %s", message)
	} else {
		log.Warnln("[TUN] %s", message)
	}
}

func clearTunRouteClaim() {
	resolver.TunRouteClaimed.Store(nil)
}

func prefixesText(prefixes []netip.Prefix) string {
	texts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		texts = append(texts, prefix.String())
	}
	return strings.Join(texts, ", ")
}
