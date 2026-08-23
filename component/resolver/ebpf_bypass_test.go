package resolver

import (
	"net/netip"
	"strings"
	"testing"

	"go4.org/netipx"
)

func prefixSet(t *testing.T, prefixes ...string) *netipx.IPSet {
	t.Helper()
	var builder netipx.IPSetBuilder
	for _, text := range prefixes {
		builder.AddPrefix(netip.MustParsePrefix(text))
	}
	set, err := builder.IPSet()
	if err != nil {
		t.Fatalf("build set: %s", err)
	}
	return set
}

func parsePrefixes(t *testing.T, prefixes ...string) []netip.Prefix {
	t.Helper()
	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, text := range prefixes {
		parsed = append(parsed, netip.MustParsePrefix(text))
	}
	return parsed
}

func prefixTexts(prefixes []netip.Prefix) []string {
	texts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		texts = append(texts, prefix.String())
	}
	return texts
}

func restoreClaimState(t *testing.T) {
	t.Helper()
	claim := TunRouteClaimed.Load()
	policy := EBPFBypassPolicyValue.Load()
	t.Cleanup(func() {
		TunRouteClaimed.Store(claim)
		EBPFBypassPolicyValue.Store(policy)
	})
}

func storePolicy(t *testing.T, tunDirect bool, prefixes ...string) {
	t.Helper()
	parsed := parsePrefixes(t, prefixes...)
	var builder netipx.IPSetBuilder
	for _, prefix := range parsed {
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	if err != nil {
		t.Fatalf("build set: %s", err)
	}
	EBPFBypassPolicyValue.Store(&EBPFBypassPolicy{Prefixes: parsed, Set: set, TunDirect: tunDirect})
}

func TestTunClaimedPrefixesNoClaim(t *testing.T) {
	restoreClaimState(t)
	TunRouteClaimed.Store(nil)
	if claimed := TunClaimedPrefixes(parsePrefixes(t, "10.0.0.0/8")); claimed != nil {
		t.Fatalf("expected no claim, got %v", claimed)
	}
	// A published claim that claims nothing must read the same way.
	TunRouteClaimed.Store(&TunRouteClaim{})
	if claimed := TunClaimedPrefixes(parsePrefixes(t, "10.0.0.0/8")); claimed != nil {
		t.Fatalf("expected no claim, got %v", claimed)
	}
}

func TestTunClaimedPrefixesIntersects(t *testing.T) {
	restoreClaimState(t)
	// auto-route claims everything except the LAN, which is what the eBPF
	// route-exclude wiring is supposed to produce.
	var builder netipx.IPSetBuilder
	builder.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	builder.RemovePrefix(netip.MustParsePrefix("192.168.0.0/16"))
	claimedSet, err := builder.IPSet()
	if err != nil {
		t.Fatalf("build set: %s", err)
	}
	TunRouteClaimed.Store(&TunRouteClaim{Claimed: claimedSet})

	claimed := TunClaimedPrefixes(parsePrefixes(t, "192.168.0.0/16", "198.51.100.0/24"))
	texts := prefixTexts(claimed)
	if len(texts) != 1 || texts[0] != "198.51.100.0/24" {
		t.Fatalf("expected only the still-routed prefix, got %v", texts)
	}
}

func TestTunClaimedBypassPrefixesUsesPublishedPolicy(t *testing.T) {
	restoreClaimState(t)
	TunRouteClaimed.Store(&TunRouteClaim{Claimed: prefixSet(t, "0.0.0.0/0")})

	EBPFBypassPolicyValue.Store(nil)
	if claimed := TunClaimedBypassPrefixes(); claimed != nil {
		t.Fatalf("expected nothing without a published policy, got %v", claimed)
	}

	storePolicy(t, true, "10.0.0.0/8")
	if texts := prefixTexts(TunClaimedBypassPrefixes()); len(texts) != 1 || texts[0] != "10.0.0.0/8" {
		t.Fatalf("expected the bypassed prefix to be reported, got %v", texts)
	}
}

func TestTunBypassOverlapMessageTruncates(t *testing.T) {
	claimed := parsePrefixes(t,
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7")
	message := TunBypassOverlapMessage(claimed, false)
	if !strings.Contains(message, "claims 6 destination prefix(es)") {
		t.Fatalf("expected the full count, got %q", message)
	}
	if !strings.Contains(message, "and 2 more") {
		t.Fatalf("expected the remainder to be summarised, got %q", message)
	}
	if strings.Contains(message, "fc00::/7") {
		t.Fatalf("expected the list to stop at the cap, got %q", message)
	}
	if !strings.Contains(message, "route-exclude-address") {
		t.Fatalf("expected the remedy to be named, got %q", message)
	}
}

func TestTunBypassOverlapMessageShortList(t *testing.T) {
	message := TunBypassOverlapMessage(parsePrefixes(t, "10.0.0.0/8"), false)
	if strings.Contains(message, "more") {
		t.Fatalf("expected no remainder for a short list, got %q", message)
	}
	if !strings.Contains(message, "10.0.0.0/8") {
		t.Fatalf("expected the prefix to be listed, got %q", message)
	}
}

func TestEBPFBypassedDirect(t *testing.T) {
	restoreClaimState(t)

	EBPFBypassPolicyValue.Store(nil)
	if EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected no direct decision without a policy")
	}

	// The mechanism has to stay switchable: a split setup can bypass a range in
	// eBPF precisely so TUN handles it.
	storePolicy(t, false, "10.0.0.0/8")
	if EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected bypass_tun_direct: false to be honoured")
	}

	storePolicy(t, true, "10.0.0.0/8")
	if !EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected a bypassed destination to be direct")
	}
	if EBPFBypassedDirect(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("expected an unbypassed destination to keep matching rules")
	}
	// A v4-in-v6 destination is the same address as far as the policy goes.
	if !EBPFBypassedDirect(netip.MustParseAddr("::ffff:10.1.2.3")) {
		t.Fatal("expected a v4-mapped address to match the v4 policy")
	}
	if EBPFBypassedDirect(netip.Addr{}) {
		t.Fatal("expected an invalid address to be ignored")
	}
}

func TestTunBypassOverlapMessageNamesTheHandler(t *testing.T) {
	claimed := parsePrefixes(t, "10.0.0.0/8")
	if handled := TunBypassOverlapMessage(claimed, true); !strings.Contains(handled, "connected directly on arrival") {
		t.Fatalf("expected the handled case to say so, got %q", handled)
	}
	if unhandled := TunBypassOverlapMessage(claimed, false); strings.Contains(unhandled, "connected directly on arrival") {
		t.Fatalf("expected the unhandled case to ask for a fix, got %q", unhandled)
	}
}
