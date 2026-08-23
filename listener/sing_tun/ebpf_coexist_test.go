package sing_tun

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"

	tun "github.com/metacubex/sing-tun"

	"go4.org/netipx"
)

func restoreCoexistState(t *testing.T) {
	t.Helper()
	excludes := resolver.EBPFRouteExcludePrefixes.Load()
	claim := resolver.TunRouteClaimed.Load()
	policy := resolver.EBPFBypassPolicyValue.Load()
	ipv4, ipv6 := resolver.FakeIPRanges()
	t.Cleanup(func() {
		resolver.EBPFRouteExcludePrefixes.Store(excludes)
		resolver.TunRouteClaimed.Store(claim)
		resolver.EBPFBypassPolicyValue.Store(policy)
		resolver.StoreFakeIPRanges(ipv4, ipv6)
	})
}

func publishExcludes(prefixes ...string) {
	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, text := range prefixes {
		parsed = append(parsed, netip.MustParsePrefix(text))
	}
	resolver.EBPFRouteExcludePrefixes.Store(&parsed)
}

func prefixTexts(prefixes []netip.Prefix) []string {
	texts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		texts = append(texts, prefix.String())
	}
	return texts
}

// Nothing published means no eBPF inbound is running with a bypass policy, and
// TUN must then route exactly what it was configured to route. A config that
// carries an eBPF listener the kernel refused to load must not quietly change
// how traffic is routed.
func TestEBPFRouteExcludeAddressNothingPublished(t *testing.T) {
	restoreCoexistState(t)
	resolver.EBPFRouteExcludePrefixes.Store(nil)
	resolver.StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})
	if excluded := ebpfRouteExcludeAddress(nil, nil); excluded != nil {
		t.Fatalf("expected no exclusions, got %v", excluded)
	}
	empty := []netip.Prefix{}
	resolver.EBPFRouteExcludePrefixes.Store(&empty)
	if excluded := ebpfRouteExcludeAddress(nil, nil); excluded != nil {
		t.Fatalf("expected no exclusions for an empty policy, got %v", excluded)
	}
}

func TestEBPFRouteExcludeAddressPassesPolicyThrough(t *testing.T) {
	restoreCoexistState(t)
	publishExcludes("10.0.0.0/8", "192.168.0.0/16")
	resolver.StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})
	texts := prefixTexts(ebpfRouteExcludeAddress(nil, nil))
	if len(texts) != 2 || texts[0] != "10.0.0.0/8" || texts[1] != "192.168.0.0/16" {
		t.Fatalf("expected both prefixes, got %v", texts)
	}
}

// A fake-ip range inside a bypassed range has to stay on the TUN routes: the
// address only means something to mihomo, and the eBPF program forces
// interception for it rather than bypassing it.
func TestEBPFRouteExcludeAddressKeepsFakeIPRange(t *testing.T) {
	restoreCoexistState(t)
	publishExcludes("100.64.0.0/10")
	resolver.StoreFakeIPRanges(netip.MustParsePrefix("100.64.0.0/16"), netip.Prefix{})
	texts := prefixTexts(ebpfRouteExcludeAddress(nil, nil))
	for _, text := range texts {
		if text == "100.64.0.0/10" || text == "100.64.0.0/16" {
			t.Fatalf("fake-ip range was excluded from the routes: %v", texts)
		}
	}
	if len(texts) == 0 {
		t.Fatal("expected the rest of the bypassed range to stay excluded")
	}
	// The hole must be exactly the fake-ip range: 100.65.0.0 is still bypassed.
	var covered bool
	for _, prefix := range ebpfRouteExcludeAddress(nil, nil) {
		if prefix.Contains(netip.MustParseAddr("100.65.0.1")) {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("expected the non-fake part to stay excluded, got %v", texts)
	}
}

func TestEBPFRouteExcludeAddressKeepsTunAddresses(t *testing.T) {
	restoreCoexistState(t)
	publishExcludes("fc00::/7")
	resolver.StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})
	tunIPv6 := []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}
	for _, prefix := range ebpfRouteExcludeAddress(nil, tunIPv6) {
		if prefix.Contains(netip.MustParseAddr("fdfe:dcba:9876::1")) {
			t.Fatalf("the device's own address was excluded from its routes: %s", prefix)
		}
	}
}

func TestPublishTunRouteClaim(t *testing.T) {
	restoreCoexistState(t)
	bypassed := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("198.51.100.0/24")}
	var builder netipx.IPSetBuilder
	for _, prefix := range bypassed {
		builder.AddPrefix(prefix)
	}
	bypassSet, err := builder.IPSet()
	if err != nil {
		t.Fatalf("build set: %s", err)
	}
	resolver.EBPFBypassPolicyValue.Store(&resolver.EBPFBypassPolicy{
		Prefixes: bypassed, Set: bypassSet, TunDirect: true,
	})

	// No auto-route: nothing is taken over, so a bypass reaches the routing
	// table untouched.
	publishTunRouteClaim(&tun.Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
	})
	if claim := resolver.TunRouteClaimed.Load(); claim != nil {
		t.Fatalf("expected no claim without auto-route, got %v", claim)
	}

	publishTunRouteClaim(&tun.Options{
		AutoRoute:                true,
		Inet4Address:             []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		Inet4RouteExcludeAddress: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	claim := resolver.TunRouteClaimed.Load()
	if claim == nil || claim.Claimed == nil {
		t.Fatal("expected a published claim")
	}
	if claim.Claimed.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected the excluded prefix to be off the claim")
	}
	if !claim.Claimed.Contains(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("expected everything else to stay claimed")
	}
	overlap := prefixTexts(resolver.TunClaimedBypassPrefixes())
	if len(overlap) != 1 || overlap[0] != "198.51.100.0/24" {
		t.Fatalf("expected only the still-routed bypass prefix to be reported, got %v", overlap)
	}

	clearTunRouteClaim()
	if claim := resolver.TunRouteClaimed.Load(); claim != nil {
		t.Fatalf("expected the claim to be cleared, got %v", claim)
	}
}
