//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
)

// SetFakeIPRanges replaces the fake-ip ranges the shared TC programs use to
// force interception, and reports whether anything changed. The shared control
// record is kept in memory, so unlike the cgroup path this rewrites the whole
// record rather than reading it back.
func (b *SharedNetworkBackend) SetFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	normalizedIPv4, err := normalizeAddressPrefix("IPv4 FakeIP range", ipv4, true)
	if err != nil {
		return false, err
	}
	normalizedIPv6, err := normalizeAddressPrefix("IPv6 FakeIP range", ipv6, false)
	if err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.requireUsableLocked(); err != nil {
		return false, err
	}
	previous := b.control
	b.control.Flags &^= sharedNetworkFlagFakeIPIPv4 | sharedNetworkFlagFakeIPIPv6
	b.control.FakeIPIPv4Prefix = [4]byte{}
	b.control.FakeIPIPv4Mask = [4]byte{}
	b.control.FakeIPIPv6Prefix = [16]byte{}
	b.control.FakeIPIPv6Mask = [16]byte{}
	if normalizedIPv4.IsValid() {
		b.control.Flags |= sharedNetworkFlagFakeIPIPv4
		b.control.FakeIPIPv4Prefix = normalizedIPv4.Addr().As4()
		b.control.FakeIPIPv4Mask = prefixMask4(normalizedIPv4.Bits())
	}
	if normalizedIPv6.IsValid() {
		b.control.Flags |= sharedNetworkFlagFakeIPIPv6
		b.control.FakeIPIPv6Prefix = normalizedIPv6.Addr().As16()
		b.control.FakeIPIPv6Mask = prefixMask16(normalizedIPv6.Bits())
	}
	if b.control == previous {
		return false, nil
	}
	if err = b.updateControl(); err != nil {
		b.control = previous
		return false, err
	}
	return true, nil
}
