package resolver

import (
	"net/netip"
	"testing"
)

func restoreFakeIPRanges(t *testing.T) {
	t.Helper()
	ipv4, ipv6 := FakeIPRanges()
	t.Cleanup(func() {
		StoreFakeIPRanges(ipv4, ipv6)
	})
}

func TestStoreFakeIPRangesNotifiesOnChange(t *testing.T) {
	restoreFakeIPRanges(t)
	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})

	type observed struct {
		ipv4 netip.Prefix
		ipv6 netip.Prefix
	}
	var seen []observed
	remove := RegisterFakeIPRangeObserver(func(ipv4 netip.Prefix, ipv6 netip.Prefix) {
		seen = append(seen, observed{ipv4, ipv6})
	})
	defer remove()

	ipv4 := netip.MustParsePrefix("100.64.0.0/10")
	StoreFakeIPRanges(ipv4, netip.Prefix{})
	if len(seen) != 1 || seen[0].ipv4 != ipv4 {
		t.Fatalf("expected one notification carrying the new range, got %v", seen)
	}
	if gotIPv4, gotIPv6 := FakeIPRanges(); gotIPv4 != ipv4 || gotIPv6.IsValid() {
		t.Fatalf("expected %s and no IPv6 range, got %s and %s", ipv4, gotIPv4, gotIPv6)
	}

	// An unchanged publication must not wake observers: updateDNS runs on every
	// config apply, and each notification pushes a map write into the kernel.
	StoreFakeIPRanges(ipv4, netip.Prefix{})
	if len(seen) != 1 {
		t.Fatalf("expected no notification for an unchanged value, got %v", seen)
	}

	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})
	if len(seen) != 2 || seen[1].ipv4.IsValid() {
		t.Fatalf("expected a notification clearing the range, got %v", seen)
	}
}

func TestRegisterFakeIPRangeObserverRemove(t *testing.T) {
	restoreFakeIPRanges(t)
	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})

	calls := 0
	remove := RegisterFakeIPRangeObserver(func(netip.Prefix, netip.Prefix) {
		calls++
	})
	remove()
	// A second removal must stay harmless: the inbound calls its stop path from
	// an idempotent Close.
	remove()

	StoreFakeIPRanges(netip.MustParsePrefix("198.18.0.0/16"), netip.Prefix{})
	if calls != 0 {
		t.Fatalf("expected no calls after removal, got %d", calls)
	}
}

func TestRegisterFakeIPRangeObserverNil(t *testing.T) {
	remove := RegisterFakeIPRangeObserver(nil)
	if remove == nil {
		t.Fatal("expected a usable remove function for a nil observer")
	}
	remove()
}
