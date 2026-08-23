//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"slices"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	"go4.org/netipx"
)

// A claimed-prefix overlap is a configuration condition, not a packet event:
// it holds until someone edits the config, so the default ten-second limiter
// would just repeat it forever.
const tunOverlapWarningInterval = 10 * time.Minute

// publishBypassPolicyLocked republishes the effective bypass policy and reports
// any bypassed destination a running TUN listener has taken over.
//
// Bypassing a destination in eBPF only means the socket keeps its original
// destination: the packet still follows the routing table, and TUN auto-route
// points that table at the TUN device. A bypassed destination that TUN claims is
// therefore not direct at all -- it is proxied by whatever the rule engine
// picks, which is a black hole for a LAN or otherwise proxy-unreachable address
// whenever the rules have no direct rule covering it.
//
// Two mechanisms answer that, and they split by size. The fixed private ranges
// are published for route exclusion, so TUN never claims them in the first
// place. A bypass_rule_set cannot go that way -- it resolves after the TUN
// device already baked its route set, and excluding a country-sized IP set would
// install tens of thousands of routes -- so those destinations are honoured on
// arrival instead, by bypass_tun_direct.
//
// The caller holds bypassRuleSetAccess.
func (i *Inbound) publishBypassPolicyLocked() {
	if i.bypassPrivateAddress {
		excludes := ECommon.PrivateAddressPrefixes()
		resolver.EBPFRouteExcludePrefixes.Store(&excludes)
	} else {
		resolver.EBPFRouteExcludePrefixes.Store(nil)
	}
	prefixes := i.effectiveBypassPrefixesLocked()
	if len(prefixes) == 0 {
		resolver.EBPFBypassPolicyValue.Store(nil)
		return
	}
	// An interface change republishes an unchanged policy, and building the
	// membership set means sorting every prefix of a rule set that can hold
	// thousands. Only the overlap report below has to run every time.
	published := resolver.EBPFBypassPolicyValue.Load()
	if published == nil ||
		published.TunDirect != i.bypassTUNDirect ||
		!slices.Equal(published.Prefixes, prefixes) {
		var builder netipx.IPSetBuilder
		for _, prefix := range prefixes {
			builder.AddPrefix(prefix)
		}
		set, err := builder.IPSet()
		if err != nil {
			// Without the set there is no membership test, and publishing the
			// policy without one would quietly disable bypass_tun_direct.
			log.Warnln("[EBPF] compile the bypass policy for TUN coexistence: %s", err.Error())
			resolver.EBPFBypassPolicyValue.Store(nil)
			return
		}
		resolver.EBPFBypassPolicyValue.Store(&resolver.EBPFBypassPolicy{
			Prefixes:  prefixes,
			Set:       set,
			TunDirect: i.bypassTUNDirect,
		})
	}
	claimed := resolver.TunClaimedPrefixes(prefixes)
	if len(claimed) == 0 {
		return
	}
	i.tunOverlapWarnings.warn(
		tunOverlapLogger(i.bypassTUNDirect),
		resolver.TunBypassOverlapMessage(claimed, i.bypassTUNDirect),
	)
}

// An overlap that is already handled on arrival is worth knowing about -- those
// flows pay a userspace hop they were configured to skip -- but it is not a
// misconfiguration, so it does not deserve a warning.
func tunOverlapLogger(tunDirect bool) warningLogger {
	if tunDirect {
		return log.Infoln
	}
	return log.Warnln
}

func (i *Inbound) effectiveBypassPrefixesLocked() []netip.Prefix {
	var prefixes []netip.Prefix
	if i.bypassPrivateAddress {
		prefixes = append(prefixes, ECommon.PrivateAddressPrefixes()...)
	}
	return append(prefixes, i.bypassCIDR...)
}
