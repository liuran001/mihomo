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

// publisher returns a registry slot that removes itself when the test ends, so
// one test's policy never leaks into the next.
func publisher(t *testing.T) *EBPFBypassPublisher {
	t.Helper()
	p := NewEBPFBypassPublisher()
	t.Cleanup(p.Close)
	return p
}

func claimEverything(t *testing.T) {
	t.Helper()
	previous := TunRouteClaimed.Load()
	TunRouteClaimed.Store(&TunRouteClaim{Claimed: prefixSet(t, "0.0.0.0/0")})
	t.Cleanup(func() { TunRouteClaimed.Store(previous) })
}

func TestTunClaimedPrefixesNoClaim(t *testing.T) {
	previous := TunRouteClaimed.Load()
	t.Cleanup(func() { TunRouteClaimed.Store(previous) })

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
	previous := TunRouteClaimed.Load()
	t.Cleanup(func() { TunRouteClaimed.Store(previous) })

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
	claimEverything(t)

	if claimed := TunClaimedBypassPrefixes(); claimed != nil {
		t.Fatalf("expected nothing without a published policy, got %v", claimed)
	}

	publisher(t).Publish(nil, parsePrefixes(t, "10.0.0.0/8"), nil, true)
	if texts := prefixTexts(TunClaimedBypassPrefixes()); len(texts) != 1 || texts[0] != "10.0.0.0/8" {
		t.Fatalf("expected the bypassed prefix to be reported, got %v", texts)
	}
}

// Several eBPF inbounds can run at once, so the published state is a union and
// each publisher owns only its own contribution.
func TestEBPFBypassPublisherUnion(t *testing.T) {
	first := publisher(t)
	second := publisher(t)

	first.Publish(nil, parsePrefixes(t, "10.0.0.0/8"), parsePrefixes(t, "10.0.0.0/8"), true)
	second.Publish(nil, parsePrefixes(t, "192.168.0.0/16"), parsePrefixes(t, "192.168.0.0/16"), true)

	policy := EBPFBypassPolicyValue.Load()
	if policy == nil || len(policy.Prefixes) != 2 {
		t.Fatalf("expected both inbounds' prefixes, got %v", policy)
	}
	if !EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) ||
		!EBPFBypassedDirect(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("expected both inbounds' destinations to be direct")
	}
	if excludes := EBPFRouteExcludePrefixes.Load(); excludes == nil || len(*excludes) != 2 {
		t.Fatalf("expected both inbounds' route exclusions, got %v", excludes)
	}

	// Closing one must leave the other's policy standing. This is the case that
	// broke before: an inbound that fails to start closes itself.
	second.Close()
	if !EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected the surviving inbound's policy to stay published")
	}
	if EBPFBypassedDirect(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("expected the closed inbound's policy to be dropped")
	}
	if excludes := EBPFRouteExcludePrefixes.Load(); excludes == nil || len(*excludes) != 1 {
		t.Fatalf("expected only the surviving route exclusion, got %v", excludes)
	}

	first.Close()
	if EBPFBypassPolicyValue.Load() != nil || EBPFRouteExcludePrefixes.Load() != nil {
		t.Fatal("expected everything to be cleared once the last inbound closed")
	}
}

// A publisher that never published anything -- an inbound whose start failed
// before it got that far -- must not disturb the others when it closes.
func TestEBPFBypassPublisherCloseWithoutPublish(t *testing.T) {
	running := publisher(t)
	running.Publish(nil, parsePrefixes(t, "10.0.0.0/8"), nil, true)

	NewEBPFBypassPublisher().Close()
	if !EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected the running inbound's policy to survive")
	}
	// And closing twice stays harmless: Close is reached from an idempotent
	// inbound Close.
	running.Close()
	running.Close()
	if EBPFBypassPolicyValue.Load() != nil {
		t.Fatal("expected the policy to be cleared")
	}
}

// bypass_tun_direct is per inbound, so only the prefixes of the inbounds that
// asked for it may be forced direct.
func TestEBPFBypassPublisherTunDirectIsPerInbound(t *testing.T) {
	direct := publisher(t)
	split := publisher(t)
	direct.Publish(nil, parsePrefixes(t, "10.0.0.0/8"), nil, true)
	split.Publish(nil, parsePrefixes(t, "192.168.0.0/16"), nil, false)

	if !EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected the opted-in inbound's destination to be direct")
	}
	if EBPFBypassedDirect(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("expected bypass_tun_direct: false to be honoured for its own prefixes")
	}
	// Both are still reported as bypassed, since both are claimed by TUN.
	claimEverything(t)
	if texts := prefixTexts(TunClaimedBypassPrefixes()); len(texts) != 2 {
		t.Fatalf("expected both inbounds' prefixes to be reported, got %v", texts)
	}
}

// The DNS fake-ip middleware reads a union too, and only bypass_rule_set feeds
// it: publishing the private ranges there would make every A/AAAA query
// resolve for real before fake-ip could answer it.
func TestEBPFBypassPublisherDNSSet(t *testing.T) {
	withRuleSet := publisher(t)
	privateOnly := publisher(t)

	privateOnly.Publish(nil, parsePrefixes(t, "10.0.0.0/8"), nil, true)
	if EBFPBypassIPSet.Load() != nil {
		t.Fatal("expected no DNS set from an inbound without bypass_rule_set")
	}

	withRuleSet.Publish(prefixSet(t, "203.0.113.0/24"), parsePrefixes(t, "203.0.113.0/24"), nil, true)
	dnsSet := EBFPBypassIPSet.Load()
	if dnsSet == nil || !dnsSet.Contains(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("expected the rule-set addresses in the DNS set")
	}
	if dnsSet.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected the private ranges to stay out of the DNS set")
	}

	withRuleSet.Close()
	if EBFPBypassIPSet.Load() != nil {
		t.Fatal("expected the DNS set to be cleared with its inbound")
	}
}

func TestEBPFBypassedDirect(t *testing.T) {
	if EBPFBypassedDirect(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected no direct decision without a policy")
	}

	p := publisher(t)
	p.Publish(nil, parsePrefixes(t, "10.0.0.0/8"), nil, true)
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

func TestTunBypassOverlapMessageNamesTheHandler(t *testing.T) {
	claimed := parsePrefixes(t, "10.0.0.0/8")
	if handled := TunBypassOverlapMessage(claimed, true); !strings.Contains(handled, "connected directly on arrival") {
		t.Fatalf("expected the handled case to say so, got %q", handled)
	}
	if unhandled := TunBypassOverlapMessage(claimed, false); strings.Contains(unhandled, "connected directly on arrival") {
		t.Fatalf("expected the unhandled case to ask for a fix, got %q", unhandled)
	}
}
