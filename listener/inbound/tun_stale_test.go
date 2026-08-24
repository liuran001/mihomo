package inbound

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	LC "github.com/metacubex/mihomo/listener/config"
)

// publishRouteExclude stands in for a running eBPF inbound and puts back
// whatever was published before the test.
func publishRouteExclude(t *testing.T, prefixes ...netip.Prefix) {
	t.Helper()
	previous := resolver.EBPFRouteExcludePrefixes.Load()
	t.Cleanup(func() { resolver.EBPFRouteExcludePrefixes.Store(previous) })
	if len(prefixes) == 0 {
		resolver.EBPFRouteExcludePrefixes.Store(nil)
		return
	}
	resolver.EBPFRouteExcludePrefixes.Store(&prefixes)
}

// sing_tun bakes the eBPF route exclusion into the device's route set, so a tun
// listener has to be rebuilt when an eBPF inbound starts, stops, or changes its
// bypass policy -- none of which the tun config it is compared against records.
func TestTunStaleFollowsThePublishedRouteExclusion(t *testing.T) {
	listener := &Tun{tun: LC.Tun{Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}}

	publishRouteExclude(t)
	if listener.Stale() {
		t.Fatal("expected a device built with no exclusion to match an empty publication")
	}

	publishRouteExclude(t, netip.MustParsePrefix("10.0.0.0/8"))
	if !listener.Stale() {
		t.Fatal("expected an eBPF inbound starting under the device to make it stale")
	}

	listener.ebpfExclude = listener.currentEBPFExclude()
	if listener.Stale() {
		t.Fatal("expected a device rebuilt with the current exclusion to be current")
	}

	publishRouteExclude(t)
	if !listener.Stale() {
		t.Fatal("expected an eBPF inbound stopping under the device to make it stale")
	}
}

// The device keeps reaching its own addresses, so a published prefix that only
// covers them leaves nothing to exclude and nothing to rebuild for.
func TestTunStaleIgnoresAnExclusionTheDeviceOwns(t *testing.T) {
	address := netip.MustParsePrefix("198.18.0.1/30")
	listener := &Tun{tun: LC.Tun{Inet4Address: []netip.Prefix{address}}}

	publishRouteExclude(t, address)
	if listener.Stale() {
		t.Fatalf("expected %s to be excluded from the exclusion, leaving the device current", address)
	}
}
