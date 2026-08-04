//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"os"

	"github.com/metacubex/mihomo/log"
	"github.com/sagernet/netlink"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

var cgroupIPv6ProbeDestination = net.ParseIP("2001:4860:4860::8888")

func (i *Inbound) cgroupIPv6Enabled() bool {
	return i.redirectIPv6Prefix.IsValid() && i.cgroupIPv6Mode != cgroupIPv6ModeOff
}

func probeCgroupIPv6Available() (bool, error) {
	uid := uint32(os.Getuid())
	routes, err := netlink.RouteGetWithOptions(
		cgroupIPv6ProbeDestination,
		&netlink.RouteGetOptions{UID: &uid},
	)
	if err != nil && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
		routes, err = netlink.RouteGet(cgroupIPv6ProbeDestination)
	}
	if err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) ||
			errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, E.Cause(err, "probe native IPv6 route")
	}
	for _, route := range routes {
		if routeSupportsNativeIPv6(route) {
			return true, nil
		}
	}
	return false, nil
}

func routeSupportsNativeIPv6(route netlink.Route) bool {
	switch route.Type {
	case unix.RTN_UNREACHABLE, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT, unix.RTN_THROW:
		return false
	}
	if usableNativeIPv6(route.Src) {
		return true
	}
	if route.LinkIndex <= 0 {
		return false
	}
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return false
	}
	addresses, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		if usableNativeIPv6(address.IP) {
			return true
		}
	}
	return false
}

func usableNativeIPv6(address net.IP) bool {
	return address != nil && address.To4() == nil && address.IsGlobalUnicast() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func (i *Inbound) refreshCgroupIPv6Availability(initial bool) error {
	if i.cgroupIPv6Mode != cgroupIPv6ModeAuto || !i.redirectIPv6Prefix.IsValid() {
		return nil
	}
	available, err := probeCgroupIPv6Available()
	if err != nil {
		if initial {
			i.cgroupIPv6Available = true
			log.Warnln("[EBPF] probe local cgroup IPv6 availability; keeping interception enabled: %s", err.Error())
			return nil
		}
		return err
	}
	if initial {
		i.cgroupIPv6Available = available
		return nil
	}
	backend := i.backendInstance()
	if backend == nil {
		return nil
	}
	changed, err := backend.UpdateIPv6Available(available)
	if err != nil {
		return err
	}
	if changed {
		i.cgroupIPv6Available = available
		log.Infoln("[EBPF] updated local cgroup IPv6 interception: available=%v", available)
	}
	return nil
}
