package ebpf

import (
	"net/netip"
	"slices"
)

// privateAddressPrefixes mirrors sb_ebpf_ipv4_private_address and
// sb_ebpf_ipv6_private_address in native/private_address.h. The two must be
// changed together: a consumer that plans routing around the bypass decision
// would silently diverge from the packet program otherwise.
//
// The unspecified, loopback and multicast ranges the programs also bypass are
// deliberately absent. Those are unconditional safety exceptions rather than
// policy, they cannot be turned off with bypass_private_address, and no
// consumer of this list has to reason about routing them.
var privateAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// PrivateAddressPrefixes returns the destination ranges the eBPF packet
// programs bypass while bypass_private_address is enabled.
func PrivateAddressPrefixes() []netip.Prefix {
	return slices.Clone(privateAddressPrefixes)
}
