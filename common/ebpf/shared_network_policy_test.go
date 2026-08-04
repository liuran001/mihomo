package ebpf

import (
	"net/netip"
	"testing"
)

func TestSharedNetworkPolicyFlags(t *testing.T) {
	v4 := []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}
	v6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}

	tests := []struct {
		name       string
		hostIPv4   []netip.Prefix
		hostIPv6   []netip.Prefix
		bypassIPv4 []netip.Prefix
		bypassIPv6 []netip.Prefix
		expect     uint32
	}{
		{
			name:     "host only",
			hostIPv4: v4,
			hostIPv6: v6,
			expect:   sharedNetworkFlagHostIPv4 | sharedNetworkFlagHostIPv6,
		},
		{
			name:       "bypass only",
			bypassIPv4: v4,
			bypassIPv6: v6,
			expect:     sharedNetworkFlagBypassIPv4 | sharedNetworkFlagBypassIPv6,
		},
		{
			name:       "host and bypass",
			hostIPv4:   v4,
			bypassIPv6: v6,
			expect:     sharedNetworkFlagHostIPv4 | sharedNetworkFlagBypassIPv6,
		},
		{
			name:   "empty",
			expect: 0,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			flags := computeSharedNetworkPolicyFlags(test.hostIPv4, test.hostIPv6, test.bypassIPv4, test.bypassIPv6)
			if flags != test.expect {
				t.Fatalf("expected flags 0x%x, got 0x%x", test.expect, flags)
			}
		})
	}
}
