//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/sagernet/netlink"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

var (
	sharedTCFilterList    = netlink.FilterList
	sharedTCFilterAdd     = netlink.FilterAdd
	sharedTCFilterReplace = netlink.FilterReplace
	sharedTCFilterDel     = netlink.FilterDel
)

func attachSharedTC(link netlink.Link, backend *ECommon.SharedNetworkBackend, enableIPv4 bool, priority uint16) (*sharedTCAttachment, error) {
	restoreRouteLocalnet := false
	originalArpAnnounce := ""
	if enableIPv4 {
		var err error
		restoreRouteLocalnet, err = enableSharedRouteLocalnet(link.Attrs().Name)
		if err != nil {
			return nil, err
		}
		originalArpAnnounce, err = raiseSharedArpAnnounce(link.Attrs().Name)
		if err != nil {
			if restoreRouteLocalnet {
				_ = restoreSharedRouteLocalnet(link.Attrs().Name)
			}
			return nil, err
		}
	}
	// Prefer the TCX link attachment when available; fall back to clsact.
	if priority == defaultSharedNetworkTCPriority {
		tcx, supported, tcxErr := backend.TryAttachTCX(link.Attrs().Index)
		if tcxErr != nil {
			if restoreRouteLocalnet {
				_ = restoreSharedRouteLocalnet(link.Attrs().Name)
			}
			_ = restoreSharedArpAnnounce(link.Attrs().Name, originalArpAnnounce)
			return nil, tcxErr
		}
		if supported {
			return &sharedTCAttachment{
				interfaceName:        link.Attrs().Name,
				interfaceIndex:       link.Attrs().Index,
				tcx:                  tcx,
				restoreRouteLocalnet: restoreRouteLocalnet,
				originalArpAnnounce:  originalArpAnnounce,
			}, nil
		}
	}
	if err := ensureClsact(link); err != nil {
		if restoreRouteLocalnet {
			_ = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		_ = restoreSharedArpAnnounce(link.Attrs().Name, originalArpAnnounce)
		return nil, err
	}
	egressProgramID, egressProgramTag := backend.EgressProgramIdentity()
	ingressProgramID, ingressProgramTag := backend.IngressProgramIdentity()
	egress, err := attachSharedTCFilter(
		link,
		netlink.HANDLE_MIN_EGRESS,
		backend.EgressProgramFD(),
		"sb_share_out",
		sharedEgressFilterHandle,
		priority,
		egressProgramID,
		egressProgramTag,
	)
	if err != nil {
		// installSharedTCFilter may return an active replacement together
		// with an error when cleanup of an older same-name filter fails.
		// Detach it before abandoning the attachment so Close cannot leak it.
		cleanupErr := detachSharedTCFilter(egress)
		if restoreRouteLocalnet {
			_ = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		_ = restoreSharedArpAnnounce(link.Attrs().Name, originalArpAnnounce)
		return nil, E.Errors(err, cleanupErr)
	}
	ingress, err := attachSharedTCFilter(
		link,
		netlink.HANDLE_MIN_INGRESS,
		backend.IngressProgramFD(),
		"sb_share_in",
		sharedIngressFilterHandle,
		priority,
		ingressProgramID,
		ingressProgramTag,
	)
	if err != nil {
		var routeErr error
		if restoreRouteLocalnet {
			routeErr = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		arpErr := restoreSharedArpAnnounce(link.Attrs().Name, originalArpAnnounce)
		return nil, E.Errors(err, detachSharedTCFilter(ingress), detachSharedTCFilter(egress), routeErr, arpErr)
	}
	return &sharedTCAttachment{
		interfaceName:        link.Attrs().Name,
		interfaceIndex:       link.Attrs().Index,
		ingress:              ingress,
		egress:               egress,
		restoreRouteLocalnet: restoreRouteLocalnet,
		originalArpAnnounce:  originalArpAnnounce,
	}, nil
}

func sharedRouteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRouteLocalnet(interfaceName string) (bool, error) {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) == "1" {
		return false, nil
	}
	if strings.TrimSpace(string(value)) != "0" {
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
	if err = os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return false, E.Cause(err, "enable route_localnet for ", interfaceName)
	}
	return true, nil
}

func restoreSharedRouteLocalnet(interfaceName string) error {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}

func sharedArpAnnouncePath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/arp_announce"
}

// raiseSharedArpAnnounce sets arp_announce=2 on the downstream interface.
// Redirected IPv4 replies carry a source address from the loopback redirect
// pool (127.128.0.0/9); with the default arp_announce=0 the kernel uses that
// packet source as the ARP sender address when resolving the LAN client, and
// clients discard such martian ARP requests, blackholing return traffic until
// the client refreshes the gateway neighbor entry itself. arp_announce=2
// makes the kernel always pick the interface's own primary address instead.
// It returns the original value to restore on detach, or "" when no change
// was made.
func raiseSharedArpAnnounce(interfaceName string) (string, error) {
	path := sharedArpAnnouncePath(interfaceName)
	value, err := os.ReadFile(path)
	if err != nil {
		return "", E.Cause(err, "read arp_announce for ", interfaceName)
	}
	original := strings.TrimSpace(string(value))
	if original == "2" {
		return "", nil
	}
	if err = os.WriteFile(path, []byte("2"), 0o644); err != nil {
		return "", E.Cause(err, "raise arp_announce for ", interfaceName)
	}
	return original, nil
}

func restoreSharedArpAnnounce(interfaceName string, original string) error {
	if original == "" {
		return nil
	}
	path := sharedArpAnnouncePath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read arp_announce for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "2" {
		return nil
	}
	if err = os.WriteFile(path, []byte(original), 0o644); err != nil {
		return E.Cause(err, "restore arp_announce for ", interfaceName)
	}
	return nil
}

func attachSharedTCFilter(link netlink.Link, parent uint32, programFD int, programName string, handle uint16, priority uint16, programID int, programTag string) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("shared-network eBPF program is unavailable")
	}
	filters, err := sharedTCFilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	var sameName []netlink.Filter
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			sameName = append(sameName, existing)
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		Id:           programID,
		Tag:          programTag,
		DirectAction: true,
	}
	return installSharedTCFilter(filter, sameName)
}

func installSharedTCFilter(filter *netlink.BpfFilter, sameName []netlink.Filter) (*netlink.BpfFilter, error) {
	var replaced []netlink.Filter
	for _, existing := range sameName {
		if existing.Attrs().Handle == filter.Attrs().Handle {
			if err := sharedTCFilterReplace(filter); err != nil {
				return nil, err
			}
			replaced = append(replaced, existing)
			break
		}
	}
	if len(replaced) == 0 {
		if err := sharedTCFilterAdd(filter); err != nil {
			return nil, err
		}
	}
	for _, existing := range sameName {
		if existing.Attrs().Handle == filter.Attrs().Handle {
			continue
		}
		if err := sharedTCFilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
			// Keep the replacement active. The caller will fail closed and the
			// next reconcile can discover the active filter by handle/name and
			// retry cleanup without losing the installed program.
			return filter, E.Cause(err, "remove superseded TC filter")
		}
	}
	return filter, nil
}

func detachSharedTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := sharedTCFilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func ensureClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func sharedHostAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, E.Cause(err, "list interfaces for shared-network host bypass")
	}
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		interfaceAddresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return nil, E.Cause(addressErr, "list addresses for interface ", networkInterface.Name)
		}
		for _, interfaceAddress := range interfaceAddresses {
			prefix, parseErr := netip.ParsePrefix(interfaceAddress.String())
			if parseErr == nil {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
	}
	return addresses, nil
}
