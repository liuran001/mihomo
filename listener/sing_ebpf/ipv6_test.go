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
		{"", cgroupIPv6ModeAuto},
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

func TestNormalizeSharedIPv6Mode(t *testing.T) {
	for _, test := range []struct {
		input  string
		output string
	}{
		{"", sharedIPv6ModeAlways},
		{sharedIPv6ModeAlways, sharedIPv6ModeAlways},
		{sharedIPv6ModeOff, sharedIPv6ModeOff},
	} {
		output, err := normalizeSharedIPv6Mode(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if output != test.output {
			t.Fatalf("unexpected shared IPv6 mode for %q: %q", test.input, output)
		}
	}
	if _, err := normalizeSharedIPv6Mode("prefer"); err == nil {
		t.Fatal("expected an unknown shared IPv6 mode to be rejected")
	}
}
