//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/resolver"

	"go4.org/netipx"
)

func restorePublishedPolicy(t *testing.T) {
	t.Helper()
	policy := resolver.EBPFBypassPolicyValue.Load()
	excludes := resolver.EBPFRouteExcludePrefixes.Load()
	claim := resolver.TunRouteClaimed.Load()
	t.Cleanup(func() {
		resolver.EBPFBypassPolicyValue.Store(policy)
		resolver.EBPFRouteExcludePrefixes.Store(excludes)
		resolver.TunRouteClaimed.Store(claim)
	})
}

func TestPublishBypassPolicyPrivateAddress(t *testing.T) {
	restorePublishedPolicy(t)
	resolver.TunRouteClaimed.Store(nil)
	inbound := &Inbound{bypassPrivateAddress: true}
	inbound.publishBypassPolicyLocked()

	excludes := resolver.EBPFRouteExcludePrefixes.Load()
	if excludes == nil {
		t.Fatal("expected the private ranges to be offered for route exclusion")
	}
	if len(*excludes) != len(ECommon.PrivateAddressPrefixes()) {
		t.Fatalf("expected the whole private set, got %v", *excludes)
	}
	published := resolver.EBPFBypassPolicyValue.Load()
	if published == nil || len(published.Prefixes) != len(ECommon.PrivateAddressPrefixes()) {
		t.Fatalf("expected the private set to be published as the policy, got %v", published)
	}
	if published.Set == nil || !published.Set.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("expected a usable membership set")
	}
}

// bypass_rule_set CIDRs belong in the reported policy but must never reach the
// route-exclude list: they resolve after the TUN device already baked its route
// set, and a rule set can hold thousands of prefixes.
func TestPublishBypassPolicyRuleSetIsNotRouteExcluded(t *testing.T) {
	restorePublishedPolicy(t)
	resolver.TunRouteClaimed.Store(nil)
	ruleSetPrefix := netip.MustParsePrefix("203.0.113.0/24")
	inbound := &Inbound{bypassCIDR: []netip.Prefix{ruleSetPrefix}}
	inbound.publishBypassPolicyLocked()

	if excludes := resolver.EBPFRouteExcludePrefixes.Load(); excludes != nil {
		t.Fatalf("expected no route exclusion without private bypass, got %v", *excludes)
	}
	published := resolver.EBPFBypassPolicyValue.Load()
	if published == nil || len(published.Prefixes) != 1 || published.Prefixes[0] != ruleSetPrefix {
		t.Fatalf("expected the rule-set prefix to be published, got %v", published)
	}
}

func TestPublishBypassPolicyNothingBypassed(t *testing.T) {
	restorePublishedPolicy(t)
	stale := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	resolver.EBPFBypassPolicyValue.Store(&resolver.EBPFBypassPolicy{Prefixes: stale})
	resolver.EBPFRouteExcludePrefixes.Store(&stale)

	inbound := &Inbound{}
	inbound.publishBypassPolicyLocked()
	if published := resolver.EBPFBypassPolicyValue.Load(); published != nil {
		t.Fatalf("expected a stale policy to be cleared, got %v", published)
	}
	if excludes := resolver.EBPFRouteExcludePrefixes.Load(); excludes != nil {
		t.Fatalf("expected stale route exclusions to be cleared, got %v", *excludes)
	}
}

// The whole point of the diagnostic: a bypassed prefix that TUN still routes is
// not direct, so it has to be reported rather than silently black-holed.
func TestPublishBypassPolicyReportsClaimedPrefixes(t *testing.T) {
	restorePublishedPolicy(t)
	var builder netipx.IPSetBuilder
	builder.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	claimed, err := builder.IPSet()
	if err != nil {
		t.Fatalf("build set: %s", err)
	}
	resolver.TunRouteClaimed.Store(&resolver.TunRouteClaim{Claimed: claimed})

	inbound := &Inbound{bypassCIDR: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	inbound.tunOverlapWarnings.interval = tunOverlapWarningInterval

	var warnings []string
	logged := func(format string, args ...any) {
		warnings = append(warnings, format)
	}
	inbound.publishBypassPolicyLocked()
	// publishBypassPolicyLocked logs through the package logger; re-run the
	// limiter directly to prove the overlap is what gets reported and that the
	// interval keeps it from repeating.
	overlap := resolver.TunClaimedBypassPrefixes()
	if len(overlap) != 1 || overlap[0] != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("expected the claimed bypass prefix to be reported, got %v", overlap)
	}
	inbound.tunOverlapWarnings.warn(logged, resolver.TunBypassOverlapMessage(overlap, false))
	if len(warnings) != 0 {
		t.Fatalf("expected the first report to have consumed the interval, got %v", warnings)
	}
}
