//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"
	"testing"
)

func TestNormalizeCgroupIPv6Mode(t *testing.T) {
	for _, test := range []struct {
		input  string
		output string
	}{
		{"", cgroupIPv6ModeAlways},
		{cgroupIPv6ModeAlways, cgroupIPv6ModeAlways},
		{cgroupIPv6ModeAuto, cgroupIPv6ModeAuto},
		{cgroupIPv6ModeOff, cgroupIPv6ModeOff},
	} {
		output, err := normalizeCgroupIPv6Mode(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if output != test.output {
			t.Fatalf("unexpected cgroup IPv6 mode for %q: %q", test.input, output)
		}
	}
	if _, err := normalizeCgroupIPv6Mode("prefer"); err == nil {
		t.Fatal("expected an unknown cgroup IPv6 mode to be rejected")
	}
}

func TestValidateCgroupAddressFamilies(t *testing.T) {
	ipv4 := netip.MustParsePrefix("127.128.0.0/9")
	ipv6 := netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	for _, test := range []struct {
		mode string
		ipv4 netip.Prefix
		ipv6 netip.Prefix
	}{
		{cgroupIPv6ModeAlways, ipv4, netip.Prefix{}},
		{cgroupIPv6ModeOff, ipv4, ipv6},
		{cgroupIPv6ModeAlways, netip.Prefix{}, ipv6},
		{cgroupIPv6ModeAuto, netip.Prefix{}, ipv6},
	} {
		if err := validateCgroupAddressFamilies(test.mode, test.ipv4, test.ipv6); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{cgroupIPv6ModeAlways, cgroupIPv6ModeAuto, cgroupIPv6ModeOff} {
		if err := validateCgroupAddressFamilies(mode, netip.Prefix{}, netip.Prefix{}); err == nil {
			t.Fatalf("expected empty address families to be rejected for %s", mode)
		}
	}
	if err := validateCgroupAddressFamilies(cgroupIPv6ModeOff, netip.Prefix{}, ipv6); err == nil {
		t.Fatal("expected IPv6-only cgroup with IPv6 disabled to be rejected")
	}
}

func TestUsableNativeIPv6(t *testing.T) {
	for _, address := range []string{"2001:db8::1", "fd00::1"} {
		if !usableNativeIPv6(net.ParseIP(address)) {
			t.Fatalf("expected %s to be usable", address)
		}
	}
	for _, address := range []string{"", "127.0.0.1", "::", "::1", "fe80::1", "ff02::1"} {
		if usableNativeIPv6(net.ParseIP(address)) {
			t.Fatalf("expected %q to be unusable", address)
		}
	}
}

func TestNormalizeSourceCIDRs(t *testing.T) {
	v4 := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.1/32"),
	}
	normalized, err := normalizeSourceCIDRs(v4)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 2 {
		t.Fatalf("unexpected normalized length: %d", len(normalized))
	}
	if normalized[0] != v4[0].Masked() {
		t.Fatalf("expected masked prefix, got %s", normalized[0])
	}
}
