//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
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
	var routeExclude []netip.Prefix
	if i.bypassPrivateAddress {
		routeExclude = ECommon.PrivateAddressPrefixes()
	}
	prefixes := i.effectiveBypassPrefixesLocked(routeExclude)
	i.bypassPublisher.Publish(i.dnsBypassSet, prefixes, routeExclude, i.bypassTUNDirect)
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

// effectiveBypassPrefixesLocked joins the private ranges the caller already
// materialised with the resolved bypass_rule_set CIDRs, so the fixed list is
// cloned once per publish rather than once per use.
//
// The full slice expression caps privateRanges at its own length, so appending a
// CIDR always allocates rather than writing into an array the caller still holds
// and hands to Publish itself. Today's private list has no spare capacity to
// write into anyway, so that cap is a guard against the list growing, not a
// saving. With no CIDRs to add the result aliases privateRanges instead, which
// is safe only because the registry treats every slice it is handed as
// read-only.
func (i *Inbound) effectiveBypassPrefixesLocked(privateRanges []netip.Prefix) []netip.Prefix {
	return append(privateRanges[:len(privateRanges):len(privateRanges)], i.bypassCIDR...)
}
