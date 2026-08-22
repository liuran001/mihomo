//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/network"
)

// minimumUDPTimeout bounds udp-timeout from below. The periodic sweeper derives
// its tick interval and the map stale-age from this value, so a near-zero
// timeout would evict live sessions on every tick.
const minimumUDPTimeout = 5 * time.Second

// Listener is the eBPF inbound listener.
type Listener interface {
	Close() error
	Address() string
}

var (
	redirectIPv4Candidates = []netip.Prefix{
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("127.64.0.0/10"),
	}
	redirectIPv6Candidates = []netip.Prefix{
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		netip.MustParsePrefix("fd53:696e:672d:6270::/64"),
	}
)

type Inbound struct {
	ctx       context.Context
	tunnel    C.Tunnel
	additions []inbound.Addition
	options   LC.EBPF

	cgroupEnabled            bool
	sharedNetworkEnabled     bool
	cgroupPath               string
	enableTCP                bool
	enableUDP                bool
	dnsMode                  string
	cgroupIPv6Mode           string
	cgroupIPv6Available      bool
	cgroupIPv6Probe          cgroupIPv6ProbeState
	cgroupIPv6ProbeLock      sync.Mutex
	sharedIPv6Mode           string
	redirectIPv4Prefix       netip.Prefix
	redirectIPv6Prefix       netip.Prefix
	cgroupMapCapacity        ECommon.CgroupMapCapacity
	cgroupPolicy             ECommon.CgroupPolicy
	androidUIDOptions        *androidUIDOptions
	udpTimeout               time.Duration
	bypassPrivateAddress     bool
	sharedNetworkMapCapacity ECommon.SharedNetworkMapCapacities
	sharedNetworkIncludeMAC  []ECommon.MACAddress
	sharedNetworkExcludeMAC  []ECommon.MACAddress

	listeners internalListenerSet

	sharedNetwork *sharedNetwork

	backendAccess sync.RWMutex
	backend       *ECommon.CgroupBackend

	protectRegistered bool

	localRoutes []*localRoute

	udpClientTable udpClientTable
	udpWarnings    udpWarningLimiters

	tcpRedirectPressure *mapPressureWatcher
	udpRedirectPressure *mapPressureWatcher

	bypassRuleSetAccess   sync.Mutex
	bypassRuleSet         []P.RuleProvider
	bypassRuleSetCallback io.Closer
	bypassRuleSetStarted  bool
	bypassCIDR            []netip.Prefix
	bypassRuleSetPolicy   ECommon.BypassCIDRPolicy
	bypassRuleSetDirty    bool

	udpPeriodicStop chan struct{}
	udpPeriodicDone chan struct{}

	closeOnce sync.Once
}

// New creates, prepares, and attaches the eBPF inbound.
func New(ctx context.Context, options LC.EBPF, tunnel C.Tunnel, additions ...inbound.Addition) (Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{inbound.WithInName("DEFAULT-EBPF")}
	}
	_, cgroupEnabled, sharedNetworkEnabled, err := normalizeMode(options.Mode)
	if err != nil {
		return nil, err
	}
	if err = validateLocalOptions(cgroupEnabled, options.Local); err != nil {
		return nil, err
	}
	if err = validateSharedOptions(sharedNetworkEnabled, options.Shared); err != nil {
		return nil, err
	}
	if err = validateAndroidUIDOptions(runtime.GOOS, options.Local); err != nil {
		return nil, err
	}
	cgroupPath, err := normalizeCgroupPath(options.Local.CgroupPath)
	if err != nil {
		return nil, err
	}
	dnsMode, err := normalizeDNSMode(options.DNSMode)
	if err != nil {
		return nil, err
	}
	cgroupIPv6Mode, err := normalizeCgroupIPv6Mode(options.Local.IPv6Mode)
	if err != nil {
		return nil, err
	}
	sharedIPv6Mode, err := normalizeSharedIPv6Mode(options.Shared.IPv6Mode)
	if err != nil {
		return nil, err
	}
	cgroupMapCapacity, err := normalizeCgroupMapCapacity(options.Local.StateCapacity)
	if err != nil {
		return nil, err
	}
	includeUIDRanges, err := parseUIDRanges(options.Local.IncludeUID, options.Local.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUIDRanges, err := parseUIDRanges(options.Local.ExcludeUID, options.Local.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	sharedNetworkOptions := LC.EBPFShared{}
	if sharedNetworkEnabled {
		sharedNetworkOptions, err = normalizeSharedNetworkOptions(options.Shared)
		if err != nil {
			return nil, err
		}
	}
	sharedNetworkIncludeMAC, err := parseSharedNetworkMACAddresses("include_mac_address", sharedNetworkOptions.IncludeMACAddress)
	if err != nil {
		return nil, err
	}
	sharedNetworkExcludeMAC, err := parseSharedNetworkMACAddresses("exclude_mac_address", sharedNetworkOptions.ExcludeMACAddress)
	if err != nil {
		return nil, err
	}
	sharedNetworkMapCapacity, err := normalizeSharedNetworkMapCapacity(sharedNetworkOptions.StateCapacity)
	if err != nil {
		return nil, err
	}
	enableTCP, enableUDP := parseNetworkOptions(options.Network)
	if !enableTCP && !enableUDP {
		return nil, E.New("eBPF inbound network must include tcp or udp")
	}
	if err = validateSharedNetworkProtocols(sharedNetworkEnabled, enableUDP, dnsMode); err != nil {
		return nil, err
	}
	udpTimeout := resolveUDPTimeout(options.UDPTimeout)
	bypassPrivateAddress := options.BypassPrivateAddress == nil || *options.BypassPrivateAddress

	inboundListener := &Inbound{
		ctx:                      ctx,
		tunnel:                   tunnel,
		additions:                additions,
		options:                  options,
		cgroupEnabled:            cgroupEnabled,
		sharedNetworkEnabled:     sharedNetworkEnabled,
		cgroupPath:               cgroupPath,
		enableTCP:                enableTCP,
		enableUDP:                enableUDP,
		dnsMode:                  dnsMode,
		cgroupIPv6Mode:           cgroupIPv6Mode,
		cgroupIPv6Available:      true,
		sharedIPv6Mode:           sharedIPv6Mode,
		redirectIPv4Prefix:       redirectIPv4Candidates[0],
		redirectIPv6Prefix:       redirectIPv6Candidates[0],
		cgroupMapCapacity:        cgroupMapCapacity,
		udpTimeout:               udpTimeout,
		bypassPrivateAddress:     bypassPrivateAddress,
		sharedNetworkMapCapacity: sharedNetworkMapCapacity,
		sharedNetworkIncludeMAC:  sharedNetworkIncludeMAC,
		sharedNetworkExcludeMAC:  sharedNetworkExcludeMAC,
		tcpRedirectPressure:      newMapPressureWatcher(),
		udpRedirectPressure:      newMapPressureWatcher(),
		cgroupPolicy: ECommon.CgroupPolicy{
			HijackDNS:            dnsMode != dnsModeOff,
			DNSRespectBypass:     dnsMode == dnsModeRespectBypass,
			BypassPrivateAddress: bypassPrivateAddress,
			IncludeUIDConfigured: len(options.Local.IncludeUID) > 0 ||
				len(options.Local.IncludeUIDRange) > 0 || len(options.Local.IncludePackage) > 0,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
		androidUIDOptions: newAndroidUIDOptions(options.Local),
	}

	rp, ok := tunnel.(P.Tunnel)
	if !ok {
		return nil, E.New("tunnel does not expose rule providers")
	}
	for _, ruleSetTag := range options.BypassRuleSet {
		ruleSet, loaded := rp.RuleProviders()[ruleSetTag]
		if !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		inboundListener.bypassRuleSet = append(inboundListener.bypassRuleSet, ruleSet)
	}

	if sharedNetworkEnabled {
		inboundListener.sharedNetwork = newSharedNetwork(
			inboundListener,
			sharedNetworkOptions,
			sharedNetworkMapCapacity,
		)
	}

	if err = inboundListener.start(); err != nil {
		_ = inboundListener.Close()
		return nil, err
	}
	return inboundListener, nil
}

func parseNetworkOptions(networks []string) (tcp bool, udp bool) {
	if len(networks) == 0 {
		return true, true
	}
	for _, networkName := range networks {
		switch strings.ToLower(networkName) {
		case network.NetworkTCP:
			tcp = true
		case network.NetworkUDP:
			udp = true
		}
	}
	return
}

func (i *Inbound) start() error {
	if i.cgroupEnabled {
		if i.androidUIDOptions != nil {
			if err := i.resolveAndroidUIDPolicy(); err != nil {
				return err
			}
		}
		if err := i.refreshCgroupIPv6Availability(true); err != nil {
			return err
		}
		policy := i.cgroupPolicy
		policy.EnableBypassCIDR = true
		backend, err := ECommon.PrepareCgroup(ECommon.CgroupConfig{
			Path:          i.cgroupPath,
			EnableTCP:     i.enableTCP,
			EnableUDP:     i.enableUDP,
			EnableIPv6:    i.cgroupIPv6Enabled(),
			AutoIPv6:      i.cgroupIPv6Mode == cgroupIPv6ModeAuto && i.cgroupIPv6Enabled(),
			IPv6Available: i.cgroupIPv6Available,
			RedirectIPv4:  i.redirectIPv4Prefix,
			RedirectIPv6:  i.redirectIPv6Prefix,
			MapCapacity:   i.cgroupMapCapacity,
			UDPTimeout:    i.udpTimeout,
			Policy:        policy,
		})
		if err != nil {
			return err
		}
		i.setBackend(backend)

		if protectFunc := backend.SocketProtectFunc(); protectFunc != nil {
			dialer.RegisterSocketProtectFunc(func(_ context.Context, network, address string, rawConn syscall.RawConn) error {
				return protectFunc(network, address, rawConn)
			})
			i.protectRegistered = true
		}

		if err = i.startBypassRuleSets(); err != nil {
			return err
		}
		if err = i.setupLocalRoutes(); err != nil {
			return err
		}
		if err = i.listeners.start(
			i.enableTCP,
			i.enableUDP,
			i.redirectIPv4Prefix.IsValid(),
			i.cgroupIPv6Enabled(),
			i.newListener,
		); err != nil {
			return err
		}
		if err = backend.LoadPrograms(i.listeners.selectedPort()); err != nil {
			return err
		}
		if i.sharedNetwork != nil {
			if err = i.sharedNetwork.Start(backend); err != nil {
				return err
			}
		}
		if err = backend.Attach(); err != nil {
			return err
		}

		i.startUDPPeriodic()

		bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
		if i.cgroupIPv6Mode == cgroupIPv6ModeAuto && i.cgroupIPv6Enabled() {
			log.Infoln("[EBPF] local cgroup IPv6 interception: available=%v", i.cgroupIPv6Available)
		}
		log.Infoln("[EBPF] inbound attached: cgroup=%s, listen_port=%d, dns_mode=%s, local_ipv6_mode=%s, self_bypass=%s, redirect_address=[%s], bypass_cidr={ipv4:%d, ipv6:%d}, programs=[%s]",
			backend.CgroupPath(),
			i.listeners.selectedPort(),
			i.dnsMode,
			i.cgroupIPv6Mode,
			backend.SelfBypassMode(),
			strings.Join(i.redirectAddressStrings(), ", "),
			bypassIPv4Count,
			bypassIPv6Count,
			strings.Join(backend.AttachedPrograms(), ", "),
		)
		if len(i.bypassRuleSet) > 0 {
			log.Infoln("[EBPF] bypass_rule_set will populate after rule-providers finish loading; see the next 'refreshed bypass CIDR policy' log")
		}
	} else if i.sharedNetworkEnabled {
		// Shared-only mode: the shared network backend does not need a cgroup
		// backend, but the inbound must still create its listeners.
		if err := i.listeners.start(
			i.enableTCP,
			i.enableUDP,
			i.redirectIPv4Prefix.IsValid(),
			false,
			i.newListener,
		); err != nil {
			return err
		}
		if i.sharedNetwork != nil {
			if err := i.sharedNetwork.Start(nil); err != nil {
				return err
			}
		}
	}
	reportKernelCapabilities(
		i.kernelProbeMode(),
		i.options.Network,
		i.backendCgroupPath(),
		i.firstSharedInterface(),
	)
	return nil
}

func (i *Inbound) kernelProbeMode() ECommon.KernelProbeMode {
	switch {
	case i.cgroupEnabled && i.sharedNetworkEnabled:
		return ECommon.KernelProbeModeAll
	case i.sharedNetworkEnabled:
		return ECommon.KernelProbeModeSharedNetwork
	default:
		return ECommon.KernelProbeModeLocal
	}
}

func (i *Inbound) firstSharedInterface() string {
	if i.sharedNetwork == nil || len(i.sharedNetwork.interfaces) == 0 {
		return ""
	}
	return i.sharedNetwork.interfaces[0]
}

func (i *Inbound) Close() error {
	var closeErr error
	i.closeOnce.Do(func() {
		i.stopUDPPeriodic()
		i.stopBypassRuleSets()
		resolver.EBFPBypassIPSet.Store(nil)
		if i.sharedNetwork != nil {
			closeErr = i.sharedNetwork.Close()
		}
		backend := i.backendInstance()
		if backend != nil {
			closeErr = E.Errors(closeErr, backend.Close())
			if backend.IsClosed() {
				i.setBackend(nil)
			}
		}
		i.unregisterSocketProtect()
		closeErr = E.Errors(closeErr, i.listeners.close())
		closeErr = E.Errors(closeErr, i.removeLocalRoutes())
	})
	return closeErr
}

func (i *Inbound) Address() string {
	address := "eBPF(cgroup=" + i.backendCgroupPath() + ", listen_port=" + fmt.Sprintf("%d", i.listeners.selectedPort()) + ")"
	return address
}

func (i *Inbound) backendCgroupPath() string {
	if backend := i.backendInstance(); backend != nil {
		return backend.CgroupPath()
	}
	return ""
}

func (i *Inbound) redirectAddressStrings() []string {
	addresses := make([]string, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		addresses = append(addresses, i.redirectIPv4Prefix.String())
	}
	if i.redirectIPv6Prefix.IsValid() {
		addresses = append(addresses, i.redirectIPv6Prefix.String())
	}
	return addresses
}

// sharedRedirectIPv6Prefix returns the shared-network IPv6 redirect prefix only
// when shared IPv6 interception is enabled.
func (i *Inbound) sharedRedirectIPv6Prefix() netip.Prefix {
	if i.sharedIPv6Mode == sharedIPv6ModeAlways {
		return i.redirectIPv6Prefix
	}
	return netip.Prefix{}
}

func (i *Inbound) backendInstance() *ECommon.CgroupBackend {
	i.backendAccess.RLock()
	defer i.backendAccess.RUnlock()
	return i.backend
}

func (i *Inbound) setBackend(backend *ECommon.CgroupBackend) {
	i.backendAccess.Lock()
	i.backend = backend
	i.backendAccess.Unlock()
}

func (i *Inbound) unregisterSocketProtect() {
	if !i.protectRegistered {
		return
	}
	dialer.UnregisterSocketProtectFunc()
	i.protectRegistered = false
}

// InterfaceUpdated notifies the shared-network TC manager that interfaces may
// have changed, so it can attach/detach downstream interfaces. It also refreshes
// the local host-address maps (the bypass rule-set policy is untouched).
func (i *Inbound) InterfaceUpdated() {
	i.bypassRuleSetAccess.Lock()
	if i.bypassRuleSetStarted {
		if _, err := i.applyBypassCIDRLocked(); err != nil {
			log.Warnln("[EBPF] refresh local interface host addresses: %s", err.Error())
		}
	}
	i.bypassRuleSetAccess.Unlock()
	if err := i.refreshCgroupIPv6Availability(false); err != nil {
		log.Warnln("[EBPF] refresh local cgroup IPv6 availability: %s", err.Error())
	}
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}

func (i *Inbound) startUDPPeriodic() {
	i.udpPeriodicStop = make(chan struct{})
	i.udpPeriodicDone = make(chan struct{})
	go i.udpPeriodicLoop(i.udpPeriodicStop, i.udpPeriodicDone)
}

func (i *Inbound) stopUDPPeriodic() {
	if i.udpPeriodicStop == nil {
		return
	}
	close(i.udpPeriodicStop)
	<-i.udpPeriodicDone
	i.udpPeriodicStop = nil
}

// resolveUDPTimeout converts the configured udp-timeout, which is expressed in
// SECONDS exactly like listener/sing_tun does, into a duration.
//
// Reading the value as a raw time.Duration would interpret it as nanoseconds:
// `udp-timeout: 300` became 300ns, which made every sweep tick consider every
// client idle and tear down live UDP sessions (and their eBPF redirects) a few
// seconds after they were established. The floor keeps a hand-written tiny
// value from degenerating the sweeper the same way.
func resolveUDPTimeout(configured int64) time.Duration {
	if configured <= 0 {
		return 5 * time.Minute
	}
	timeout := time.Second * time.Duration(configured)
	if timeout < minimumUDPTimeout {
		return minimumUDPTimeout
	}
	return timeout
}

func (i *Inbound) udpPeriodicLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := i.udpTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	bypassTicker := time.NewTicker(3 * time.Second)
	defer bypassTicker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			i.udpClientTable.sweep(time.Now(), i.udpTimeout, func(releases []udpRedirectRelease) {
				for _, release := range releases {
					i.deleteUDPRedirects([]netip.Addr{release.reference.address})
				}
			})
			if backend := i.backendInstance(); backend != nil && !backend.IsClosed() {
				maxAge := 2 * i.udpTimeout
				if maxAge < 30*time.Second {
					maxAge = 30 * time.Second
				}
				if result, sweepErr := backend.SweepStaleTCPRedirects(maxAge, 1024); sweepErr != nil {
					i.udpWarnings.cleanup.warn(i.logWarn, "sweep stale TCP redirects: ", sweepErr)
				} else if result.Removed > 0 {
					log.Debugln("[EBPF] swept %d stale TCP redirects", result.Removed)
				}
				if result, sweepErr := backend.SweepStaleUDPRedirects(maxAge, 1024); sweepErr != nil {
					i.udpWarnings.cleanup.warn(i.logWarn, "sweep stale UDP redirects: ", sweepErr)
				} else if result.Removed > 0 {
					log.Debugln("[EBPF] swept %d stale UDP redirects", result.Removed)
				}
				// Report after sweeping: the sweep is what refreshes the count,
				// and reading it first would warn on the pre-reclaim number.
				tcpUsage, tcpUsageErr := backend.RedirectMapUsage(ECommon.ProtocolTCP)
				i.tcpRedirectPressure.observe(i.logWarn, "cgroup_tcp_redirect", tcpUsage, tcpUsageErr)
				udpUsage, udpUsageErr := backend.RedirectMapUsage(ECommon.ProtocolUDP)
				i.udpRedirectPressure.observe(i.logWarn, "cgroup_udp_redirect", udpUsage, udpUsageErr)
			}
		case <-bypassTicker.C:
			i.refreshBypassCIDRPeriodic()
		}
	}
}

func (i *Inbound) refreshBypassCIDRPeriodic() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		if backend := i.backendInstance(); backend != nil && !backend.IsClosed() {
			log.Debugln("[EBPF] refresh bypass CIDR: %s", err.Error())
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) logBypassCIDRUpdate() {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	ipv4Count, ipv6Count := backend.BypassCIDRCount()
	log.Debugln("[EBPF] refreshed bypass CIDR policy: ipv4=%d, ipv6=%d", ipv4Count, ipv6Count)
}

func localInterfacePrefixes() []netip.Prefix {
	iface.FlushCache()
	networkInterfaces, _ := iface.Interfaces()
	var prefixes []netip.Prefix
	for _, networkInterface := range networkInterfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return prefixes
}
