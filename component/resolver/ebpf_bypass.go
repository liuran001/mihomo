package resolver

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"

	"go4.org/netipx"
)

// EBFPBypassIPSet holds the current eBPF inbound bypass CIDR set. It is
// registered by the eBPF inbound and consulted by the DNS fake-ip middleware
// so that domains whose real addresses fall in the bypass set are answered
// with their real IP instead of a fake-ip, letting the kernel eBPF bypass
// engage (matching sing-box's effective behavior). It is nil when no eBPF
// inbound with a bypass policy is active.
var EBFPBypassIPSet atomic.Pointer[netipx.IPSet]

// EBPFBypassPolicy is the effective destination policy of a running eBPF
// inbound: the private ranges when bypass_private_address is on, plus the
// resolved bypass_rule_set CIDRs.
//
// It is wider than EBFPBypassIPSet, which the DNS fake-ip middleware consults
// and which is only published for bypass_rule_set. This is the whole policy, so
// other components can tell what the kernel is letting through.
type EBPFBypassPolicy struct {
	// Prefixes is the policy as configured, for reporting.
	Prefixes []netip.Prefix
	// Set is the same policy as a membership test. Per-connection lookups go
	// through this, never through Prefixes: a bypass_rule_set holds thousands
	// of entries and a linear scan would land on the connection path.
	Set *netipx.IPSet
	// TunDirect honours the bypass for a destination a TUN listener claimed,
	// instead of handing the flow to the rule engine.
	TunDirect bool
}

// EBPFBypassPolicyValue is published by the eBPF inbound while it is running,
// and cleared when it stops.
var EBPFBypassPolicyValue atomic.Pointer[EBPFBypassPolicy]

// EBPFRouteExcludePrefixes is the subset of the bypass policy that a TUN
// listener must keep out of its routes for the bypass to mean anything.
//
// It is deliberately narrower than the policy: only the fixed private ranges
// are published here. A bypass_rule_set is resolved from rule providers that
// have not finished loading when the TUN device is created, and sing-tun bakes
// its route set at that moment, so a rule set could neither be applied in time
// nor bounded in size -- excluding a country-sized IP set would install tens of
// thousands of routes. Those destinations are handled by TunDirect instead.
var EBPFRouteExcludePrefixes atomic.Pointer[[]netip.Prefix]

// EBPFBypassedDirect reports whether a destination that only reached mihomo
// because a TUN listener claimed its route should be connected directly.
//
// The eBPF inbound already decided to let this destination past the redirect;
// the flow is here anyway because auto-route pointed the routing table at the
// TUN device. Matching it against the rules is what turns the bypass into a
// black hole: the rules were written expecting these destinations never to
// arrive, so they fall through to whatever the final rule says, and a LAN or
// geo-restricted address handed to a remote proxy simply times out.
func EBPFBypassedDirect(destination netip.Addr) bool {
	policy := EBPFBypassPolicyValue.Load()
	if policy == nil || !policy.TunDirect || policy.Set == nil {
		return false
	}
	if !destination.IsValid() {
		return false
	}
	return policy.Set.Contains(destination.Unmap())
}

// TunRouteClaim is the destination range a running TUN listener has taken over
// through auto-route, after its own route-exclude options were applied.
//
// It exists because an eBPF bypass and a TUN route exclusion are decisions at
// two different layers: bypassing a destination in eBPF only means the socket
// keeps its original destination, so the packet still follows the routing
// table, and auto-route points that table at the TUN device. A destination
// bypassed by eBPF but claimed here is therefore not direct at all -- it is
// handled by TUN and routed by the rule engine.
type TunRouteClaim struct {
	// Claimed is the set of destinations routed into the TUN device. A nil set
	// claims nothing.
	Claimed *netipx.IPSet
}

// TunRouteClaimed is published by the TUN listener while it is running with
// auto-route, and cleared when it stops. Nil means no TUN listener is claiming
// destinations, so an eBPF bypass reaches the normal routing table.
var TunRouteClaimed atomic.Pointer[TunRouteClaim]

// TunClaimedPrefixes returns the subset of prefixes that a running TUN
// listener has taken over, so the caller can report exactly which bypassed
// destinations will not be direct. It returns nil when no TUN listener is
// claiming anything.
func TunClaimedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	claim := TunRouteClaimed.Load()
	if claim == nil || claim.Claimed == nil {
		return nil
	}
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	builder.Intersect(claim.Claimed)
	overlap, err := builder.IPSet()
	if err != nil || overlap == nil {
		return nil
	}
	return overlap.Prefixes()
}

// TunClaimedBypassPrefixes returns the eBPF-bypassed destinations that a
// running TUN listener has taken over. An empty result means the two are not
// fighting over anything: either no TUN listener is claiming routes, no eBPF
// inbound is bypassing anything, or every bypassed destination was excluded
// from the TUN routes.
func TunClaimedBypassPrefixes() []netip.Prefix {
	policy := EBPFBypassPolicyValue.Load()
	if policy == nil {
		return nil
	}
	return TunClaimedPrefixes(policy.Prefixes)
}

// tunBypassOverlapPrefixes bounds how many prefixes a single overlap report
// spells out. A bypass_rule_set can hold thousands.
const tunBypassOverlapPrefixes = 4

// TunBypassOverlapMessage describes an overlap between the eBPF bypass policy
// and the destinations a TUN listener routes into its device. It lives here so
// both listeners report the condition identically -- either one can be the
// second to start, and only that one knows the overlap exists.
func TunBypassOverlapMessage(claimed []netip.Prefix, tunDirect bool) string {
	shown := claimed
	suffix := ""
	if len(shown) > tunBypassOverlapPrefixes {
		shown = shown[:tunBypassOverlapPrefixes]
		suffix = fmt.Sprintf(" and %d more", len(claimed)-tunBypassOverlapPrefixes)
	}
	texts := make([]string, 0, len(shown))
	for _, prefix := range shown {
		texts = append(texts, prefix.String())
	}
	remedy := "Add them to tun.route-exclude-address, or give the rules a matching direct rule."
	if tunDirect {
		remedy = "They are connected directly on arrival instead of being matched against the rules; " +
			"add them to tun.route-exclude-address to keep them off the TUN device entirely."
	}
	return fmt.Sprintf(
		"TUN auto-route claims %d destination prefix(es) the eBPF inbound bypasses (%s%s). %s",
		len(claimed), strings.Join(texts, ", "), suffix, remedy)
}
