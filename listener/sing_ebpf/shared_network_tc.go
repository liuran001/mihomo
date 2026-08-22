//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/log"
	"github.com/sagernet/netlink"

	E "github.com/metacubex/sing/common/exceptions"
	list "github.com/metacubex/sing/common/x/list"

	tun "github.com/metacubex/sing-tun"

	"golang.org/x/sys/unix"
)

const (
	sharedNetworkFallbackRefresh = 3 * time.Second
	// Run before Android tethering offload (IPv6 priority 2, IPv4 priority 3).
	defaultSharedNetworkTCPriority = 1
	sharedIngressFilterHandle      = 0x5342
	sharedEgressFilterHandle       = 0x5343
)

type sharedTCManager struct {
	backend         *ECommon.SharedNetworkBackend
	interfaces      []string
	enableIPv4      bool
	priority        uint16
	access          sync.Mutex
	attachments     map[string]*sharedTCAttachment
	enabled         bool
	cancel          context.CancelFunc
	done            chan struct{}
	wake            chan struct{}
	networkMonitor  tun.NetworkUpdateMonitor
	networkCallback *list.Element[tun.NetworkUpdateCallback]
	refreshWarnings warningLimiter
}

type sharedTCAttachment struct {
	interfaceName        string
	interfaceIndex       int
	tcx                  *ECommon.SharedNetworkTCXAttachment
	ingress              *netlink.BpfFilter
	egress               *netlink.BpfFilter
	restoreRouteLocalnet bool
	originalArpAnnounce  string
}

func (m *sharedTCManager) Start() error {
	if m.priority == 0 {
		m.priority = defaultSharedNetworkTCPriority
	}
	if err := m.reconcile(); err != nil {
		return E.Errors(err, m.closeAttachments())
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.wake = make(chan struct{}, 1)
	if m.networkMonitor != nil {
		if err := m.networkMonitor.Start(); err != nil {
			m.networkMonitor = nil
		} else {
			m.networkCallback = m.networkMonitor.RegisterCallback(m.Wake)
		}
	}
	go m.loop(ctx)
	return nil
}

func (m *sharedTCManager) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(sharedNetworkFallbackRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		if err := m.reconcile(); err != nil {
			m.refreshWarnings.warn(m.warnf, "refresh eBPF shared-network interfaces: ", err)
		}
	}
}

func (m *sharedTCManager) Wake() {
	if m == nil || m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *sharedTCManager) warnf(format string, args ...any) {
	log.Warnln(format, args...)
}

func (m *sharedTCManager) reconcile() error {
	hostAddresses, err := sharedHostAddresses()
	if err != nil {
		return err
	}
	if err = m.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}
	desired := make(map[string]netlink.Link, len(m.interfaces))
	for _, interfaceName := range m.interfaces {
		link, linkErr := netlink.LinkByName(interfaceName)
		if isSharedNetworkLinkNotFound(linkErr) {
			continue
		}
		if linkErr != nil {
			return E.Cause(linkErr, "find shared-network interface ", interfaceName)
		}
		if linkErr = validateSharedNetworkLink(link); linkErr != nil {
			return linkErr
		}
		desired[interfaceName] = link
	}

	m.access.Lock()
	defer m.access.Unlock()
	for interfaceName, attachment := range m.attachments {
		link, loaded := desired[interfaceName]
		if loaded && link.Attrs().Index == attachment.interfaceIndex {
			if attachment.tcx != nil {
				if _, repairErr := m.backend.RepairTCX(attachment.tcx, attachment.interfaceIndex); repairErr != nil {
					return E.Cause(repairErr, "repair shared-network TCX on ", interfaceName)
				}
				continue
			}
			if sharedTCFiltersHealthy(link, attachment) {
				continue
			}
			if err = m.detachLocked(attachment); err != nil {
				return E.Cause(err, "replace stale shared-network interface ", interfaceName)
			}
			delete(m.attachments, interfaceName)
			log.Infoln("[EBPF] shared-network repaired clsact attachment on %s", interfaceName)
			continue
		}
		if err = m.detachLocked(attachment); err != nil {
			return E.Cause(err, "detach stale shared-network interface ", interfaceName)
		}
		delete(m.attachments, interfaceName)
		log.Infoln("[EBPF] shared-network detached from %s", interfaceName)
	}
	for interfaceName, link := range desired {
		if _, loaded := m.attachments[interfaceName]; loaded {
			continue
		}
		attachment, attachErr := attachSharedTC(link, m.backend, m.enableIPv4, m.priority)
		if attachErr != nil {
			// A stale attachment may already have been removed above. If
			// replacement attach then fails, do not leave the BPF control
			// map enabled while this interface has no managed filter.
			disableErr := m.updateEnabledLocked(len(m.attachments) > 0)
			return E.Errors(
				E.Cause(attachErr, "attach eBPF shared-network to ", interfaceName),
				disableErr,
			)
		}
		m.attachments[interfaceName] = attachment
		log.Infoln("[EBPF] shared-network attached to %s (ifindex=%d)", interfaceName, link.Attrs().Index)
	}
	return m.updateEnabledLocked(len(m.attachments) > 0)
}

func sharedTCFiltersHealthy(link netlink.Link, attachment *sharedTCAttachment) bool {
	for parent, expected := range map[uint32]*netlink.BpfFilter{
		netlink.HANDLE_MIN_INGRESS: attachment.ingress,
		netlink.HANDLE_MIN_EGRESS:  attachment.egress,
	} {
		if expected == nil {
			return false
		}
		filters, err := sharedTCFilterList(link, parent)
		if err != nil {
			return false
		}
		found := false
		for _, filter := range filters {
			bpf, ok := filter.(*netlink.BpfFilter)
			if ok && sharedTCFilterMatches(bpf, expected) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sharedTCFilterMatches(current *netlink.BpfFilter, expected *netlink.BpfFilter) bool {
	if current == nil || expected == nil ||
		current.Name != expected.Name ||
		current.Attrs().Handle != expected.Attrs().Handle ||
		current.Attrs().Priority != expected.Attrs().Priority ||
		current.Attrs().Protocol != expected.Attrs().Protocol ||
		current.DirectAction != expected.DirectAction {
		return false
	}
	// Filter dumps may omit the process-local FD. Never compare Fd: a dump
	// may expose a newly allocated descriptor rather than the descriptor used
	// during attach. Program ID and tag are persistent kernel identities and
	// are safe to compare when both sides provide them.
	if current.Id != 0 && expected.Id != 0 && current.Id != expected.Id {
		return false
	}
	if current.Tag != "" && expected.Tag != "" && current.Tag != expected.Tag {
		return false
	}
	return true
}

func isSharedNetworkLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func validateSharedNetworkLink(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return E.New("invalid shared-network interface")
	}
	if len(link.Attrs().HardwareAddr) != 6 {
		return E.New("shared-network interface ", link.Attrs().Name, " is not Ethernet-like")
	}
	return nil
}

func (m *sharedTCManager) updateEnabledLocked(enabled bool) error {
	if m.enabled == enabled {
		return nil
	}
	var err error
	if enabled {
		err = m.backend.Enable()
	} else {
		err = m.backend.Disable()
	}
	if err == nil {
		m.enabled = enabled
	}
	return err
}

func (m *sharedTCManager) detachLocked(attachment *sharedTCAttachment) error {
	var detachErr error
	if attachment.tcx != nil {
		detachErr = attachment.tcx.Close()
	} else {
		detachErr = E.Errors(
			detachSharedTCFilter(attachment.ingress),
			detachSharedTCFilter(attachment.egress),
		)
	}
	var restoreErr error
	if attachment.restoreRouteLocalnet {
		restoreErr = restoreSharedRouteLocalnet(attachment.interfaceName)
	}
	return E.Errors(detachErr, restoreErr, restoreSharedArpAnnounce(attachment.interfaceName, attachment.originalArpAnnounce))
}

func (m *sharedTCManager) InterfaceString() string {
	m.access.Lock()
	defer m.access.Unlock()
	names := make([]string, 0, len(m.attachments))
	for name := range m.attachments {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "waiting for " + strings.Join(m.interfaces, ", ")
	}
	return strings.Join(names, ", ")
}

func (m *sharedTCManager) Close() error {
	if m == nil {
		return nil
	}
	if m.networkCallback != nil {
		m.networkMonitor.UnregisterCallback(m.networkCallback)
		m.networkCallback = nil
	}
	if m.networkMonitor != nil {
		_ = m.networkMonitor.Close()
		m.networkMonitor = nil
	}
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
	return m.closeAttachments()
}

func (m *sharedTCManager) closeAttachments() error {
	m.access.Lock()
	defer m.access.Unlock()
	var closeErr error
	if err := m.updateEnabledLocked(false); err != nil {
		closeErr = err
	}
	for name, attachment := range m.attachments {
		if err := m.detachLocked(attachment); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "detach shared-network interface ", name))
			continue
		}
		delete(m.attachments, name)
	}
	return closeErr
}
