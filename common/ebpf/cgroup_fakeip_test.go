//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

// The control record is read back and mutated in place at runtime, so the
// fake-ip fields have to be cleared before they are rewritten and every
// unrelated flag has to survive. Getting this wrong either strands a stale
// range in the kernel or drops an unrelated policy bit.
func TestApplyFakeIPControlReplacesRanges(t *testing.T) {
	backend := &CgroupBackend{
		fakeIPIPv4: netip.MustParsePrefix("100.64.0.0/10"),
	}
	control := cgroupControl{
		Flags:            cgroupFlagTCP | cgroupFlagHijackDNS | cgroupFlagFakeIPIPv6,
		ListenerPort:     4242,
		FakeIPIPv6Prefix: [16]byte{0: 0xfd},
		FakeIPIPv6Mask:   [16]byte{0: 0xff},
	}
	backend.applyFakeIPControlLocked(&control)

	if control.Flags&(cgroupFlagTCP|cgroupFlagHijackDNS) != cgroupFlagTCP|cgroupFlagHijackDNS {
		t.Fatalf("unrelated flags were dropped: %#x", control.Flags)
	}
	if control.Flags&cgroupFlagFakeIPIPv4 == 0 {
		t.Fatalf("expected the IPv4 fake-ip flag to be set: %#x", control.Flags)
	}
	if control.Flags&cgroupFlagFakeIPIPv6 != 0 {
		t.Fatalf("expected the stale IPv6 fake-ip flag to be cleared: %#x", control.Flags)
	}
	if control.FakeIPIPv4Prefix != [4]byte{100, 64, 0, 0} {
		t.Fatalf("unexpected IPv4 prefix: %v", control.FakeIPIPv4Prefix)
	}
	if control.FakeIPIPv4Mask != [4]byte{0xff, 0xc0, 0, 0} {
		t.Fatalf("unexpected IPv4 mask: %v", control.FakeIPIPv4Mask)
	}
	if control.FakeIPIPv6Prefix != [16]byte{} || control.FakeIPIPv6Mask != [16]byte{} {
		t.Fatal("expected the stale IPv6 range to be zeroed")
	}
	if control.ListenerPort != 4242 {
		t.Fatalf("expected the listener port to survive, got %d", control.ListenerPort)
	}
}

func TestApplyFakeIPControlClearsBothFamilies(t *testing.T) {
	backend := &CgroupBackend{}
	control := cgroupControl{
		Flags:            cgroupFlagUDP | cgroupFlagFakeIPIPv4 | cgroupFlagFakeIPIPv6,
		FakeIPIPv4Prefix: [4]byte{100, 64, 0, 0},
	}
	backend.applyFakeIPControlLocked(&control)
	if control.Flags != cgroupFlagUDP {
		t.Fatalf("expected only the unrelated flag to remain: %#x", control.Flags)
	}
	if control.FakeIPIPv4Prefix != [4]byte{} {
		t.Fatalf("expected the range to be zeroed, got %v", control.FakeIPIPv4Prefix)
	}
}

func TestSetFakeIPRangesRejectsWrongFamily(t *testing.T) {
	backend := &CgroupBackend{}
	if _, err := backend.SetFakeIPRanges(netip.MustParsePrefix("fc00::/7"), netip.Prefix{}); err == nil {
		t.Fatal("expected an IPv6 prefix in the IPv4 slot to be rejected")
	}
	if _, err := backend.SetFakeIPRanges(netip.Prefix{}, netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Fatal("expected an IPv4 prefix in the IPv6 slot to be rejected")
	}
	// A rejected range must not have been stored.
	if ipv4, ipv6 := backend.FakeIPRanges(); ipv4.IsValid() || ipv6.IsValid() {
		t.Fatalf("expected no range to be stored, got %s and %s", ipv4, ipv6)
	}
}

func TestSetFakeIPRangesNilBackend(t *testing.T) {
	var backend *CgroupBackend
	if _, err := backend.SetFakeIPRanges(netip.Prefix{}, netip.Prefix{}); err == nil {
		t.Fatal("expected a closed backend to be reported")
	}
	if ipv4, ipv6 := backend.FakeIPRanges(); ipv4.IsValid() || ipv6.IsValid() {
		t.Fatal("expected zero ranges from a nil backend")
	}
}
