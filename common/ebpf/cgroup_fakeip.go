//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// SetFakeIPRanges replaces the fake-ip ranges the packet program uses to force
// interception, and reports whether anything changed.
//
// The ranges come from the DNS configuration. That is applied before the
// inbound starts on a cold start, but it can also change under a running
// inbound when a config reload leaves the listener itself untouched. Without a
// runtime path the control record would keep whatever range the process
// started with, and a fake-ip range that sits inside a bypassed range
// (100.64.0.0/10, say) would have every fake address bypassed instead of
// proxied.
func (b *CgroupBackend) SetFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) (bool, error) {
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
	if err = b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	if normalizedIPv4 == b.fakeIPIPv4 && normalizedIPv6 == b.fakeIPIPv6 {
		return false, nil
	}
	previousIPv4, previousIPv6 := b.fakeIPIPv4, b.fakeIPIPv6
	b.fakeIPIPv4 = normalizedIPv4
	b.fakeIPIPv6 = normalizedIPv6
	if err = b.mutateCgroupControlLocked(b.applyFakeIPControlLocked); err != nil {
		b.fakeIPIPv4 = previousIPv4
		b.fakeIPIPv6 = previousIPv6
		return false, err
	}
	return true, nil
}

// FakeIPRanges reports the ranges currently compiled into the control record.
func (b *CgroupBackend) FakeIPRanges() (netip.Prefix, netip.Prefix) {
	if b == nil {
		return netip.Prefix{}, netip.Prefix{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeIPIPv4, b.fakeIPIPv6
}

func (b *CgroupBackend) applyFakeIPControlLocked(control *cgroupControl) {
	control.Flags &^= cgroupFlagFakeIPIPv4 | cgroupFlagFakeIPIPv6
	control.FakeIPIPv4Prefix = [4]byte{}
	control.FakeIPIPv4Mask = [4]byte{}
	control.FakeIPIPv6Prefix = [16]byte{}
	control.FakeIPIPv6Mask = [16]byte{}
	if b.fakeIPIPv4.IsValid() {
		control.Flags |= cgroupFlagFakeIPIPv4
		control.FakeIPIPv4Prefix = b.fakeIPIPv4.Addr().As4()
		control.FakeIPIPv4Mask = prefixMask4(b.fakeIPIPv4.Bits())
	}
	if b.fakeIPIPv6.IsValid() {
		control.Flags |= cgroupFlagFakeIPIPv6
		control.FakeIPIPv6Prefix = b.fakeIPIPv6.Addr().As16()
		control.FakeIPIPv6Mask = prefixMask16(b.fakeIPIPv6.Bits())
	}
}

// mutateCgroupControlLocked applies an in-place change to the live control
// record. Only load time knows the listener port and the self-bypass TGID, so a
// runtime change has to read the record back instead of rebuilding it. A
// missing record means the programs are not loaded yet and loadPrograms will
// write the new value itself.
func (b *CgroupBackend) mutateCgroupControlLocked(mutate func(*cgroupControl)) error {
	if b.runtime == nil {
		return errBackendClosed
	}
	if b.runtime.control_map_fd <= 0 {
		return nil
	}
	key := uint32(0)
	var control cgroupControl
	if err := lookupMap(b.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return E.Cause(err, "read eBPF cgroup control map")
	}
	previous := control
	mutate(&control)
	if control == previous {
		return nil
	}
	return updateMap(b.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control))
}
