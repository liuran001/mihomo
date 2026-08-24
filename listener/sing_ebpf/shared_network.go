//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"sync"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	tun "github.com/metacubex/sing-tun"
)

type sharedNetwork struct {
	inbound        *Inbound
	interfaces     []string
	options        LC.EBPFShared
	sharedBackend  *ECommon.SharedNetworkBackend
	tcManager      *sharedTCManager
	listeners      internalListenerSet
	udpClientTable udpClientTable
	udpWarnings    udpWarningLimiters
	mapCapacity    ECommon.SharedNetworkMapCapacities
	tcPriority     uint16
	dataPlane      string
	routingMark    uint32
	routingTable   uint32
	policyRoute    *sharedNetworkPolicyRoute

	lifecycleAccess sync.RWMutex
	backendAccess   sync.RWMutex
	periodicStop    chan struct{}
	periodicDone    chan struct{}

	janitorAccess sync.Mutex
	janitorCancel context.CancelFunc
	janitorDone   chan struct{}
}

const (
	sharedNetworkDataPlaneAuto         = "auto"
	sharedNetworkDataPlaneSocketAssign = "socket_assign"
	sharedNetworkDataPlaneRewrite      = "rewrite"
	sharedNetworkRoutingMarkDefault    = 0x53420001
	sharedNetworkRoutingTableDefault   = 2026
	sharedFlowMaxIdle                  = 5 * time.Minute
	sharedFlowPressureMaxIdle          = 15 * time.Second
	sharedFlowSweepInterval            = 5 * time.Minute
	sharedFlowPressureInterval         = 5 * time.Second
	sharedFlowPressureEnterPercent     = 70
	sharedFlowPressureExitPercent      = 50
	sharedFlowPressureExitRounds       = 3
	sharedFlowFallbackScanBudget       = 1024
	sharedFlowReleaseFlushBudget       = 4096
)

func newSharedNetwork(inbound *Inbound, sharedOptions LC.EBPFShared, mapCapacity ECommon.SharedNetworkMapCapacities) *sharedNetwork {
	tcPriority := sharedOptions.Advanced.TCPriority
	if tcPriority == 0 {
		tcPriority = defaultSharedNetworkTCPriority
	}
	dataPlane := sharedOptions.Advanced.DataPlane
	switch dataPlane {
	case "", sharedNetworkDataPlaneAuto:
		dataPlane = sharedNetworkDataPlaneAuto
	case sharedNetworkDataPlaneSocketAssign, sharedNetworkDataPlaneRewrite:
	default:
		dataPlane = sharedNetworkDataPlaneAuto
	}
	routingMark := sharedOptions.Advanced.RoutingMark
	if routingMark == 0 {
		routingMark = sharedNetworkRoutingMarkDefault
	}
	routingTable := sharedOptions.Advanced.RoutingTable
	if routingTable == 0 {
		routingTable = sharedNetworkRoutingTableDefault
	}
	return &sharedNetwork{
		inbound:      inbound,
		interfaces:   append([]string(nil), sharedOptions.Interface...),
		options:      sharedOptions,
		mapCapacity:  mapCapacity,
		tcPriority:   tcPriority,
		dataPlane:    dataPlane,
		routingMark:  routingMark,
		routingTable: routingTable,
	}
}

func (s *sharedNetwork) Start(cgroupBackend *ECommon.CgroupBackend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort:         s.listeners.selectedPort(),
		EnableTCP:            s.inbound.enableTCP,
		EnableUDP:            s.inbound.enableUDP,
		DNSMode:              commonDNSMode(s.inbound.dnsMode),
		BypassPrivateAddress: s.inbound.bypassPrivateAddress,
		RedirectIPv4:         s.inbound.redirectIPv4Prefix,
		RedirectIPv6:         s.inbound.sharedRedirectIPv6Prefix(),
		IncludeSourceCIDR:    s.options.IncludeSourceCIDR,
		ExcludeSourceCIDR:    s.options.ExcludeSourceCIDR,
		IncludeSourceMAC:     s.inbound.sharedNetworkIncludeMAC,
		ExcludeSourceMAC:     s.inbound.sharedNetworkExcludeMAC,
		MapCapacity:          s.mapCapacity,
		UDPTimeout:           s.inbound.udpTimeout,
		DataPlane:            s.dataPlane,
		RoutingMark:          s.routingMark,
	})
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	if backend.TCPAssignmentEnabled() {
		if registerErr := s.listeners.registerTCPAssignmentSockets(backend); registerErr != nil {
			if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
				return E.Errors(E.Cause(registerErr, "register shared-network TCP assignment listeners"), backend.Close())
			}
			if fallbackErr := backend.FallbackToRewrite(); fallbackErr != nil {
				return E.Errors(registerErr, fallbackErr, backend.Close())
			}
			log.Debugln("[EBPF] shared-network socket assignment unavailable; using rewrite fallback: %s", registerErr.Error())
		} else {
			policyRoute, routeErr := installSharedNetworkPolicyRoute(
				s.routingMark,
				s.routingTable,
				s.inbound.redirectIPv4Prefix.IsValid(),
				s.inbound.redirectIPv6Prefix.IsValid(),
			)
			if routeErr != nil {
				if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
					return E.Errors(routeErr, backend.Close())
				}
				if fallbackErr := backend.FallbackToRewrite(); fallbackErr != nil {
					return E.Errors(routeErr, fallbackErr, backend.Close())
				}
				log.Debugln("[EBPF] shared-network socket assignment route unavailable; using rewrite fallback: %s", routeErr.Error())
			} else {
				s.policyRoute = policyRoute
			}
		}
	}
	s.setSharedBackend(backend)
	if cgroupBackend == nil {
		if _, err = backend.UpdateBypassCIDR(s.inbound.currentBypassCIDR()); err != nil {
			return E.Errors(err, s.Close())
		}
	} else {
		ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
		if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
			return E.Errors(err, s.Close())
		}
	}
	s.tcManager = &sharedTCManager{
		backend:     backend,
		interfaces:  s.interfaces,
		enableIPv4:  s.inbound.redirectIPv4Prefix.IsValid(),
		priority:    s.tcPriority,
		attachments: make(map[string]*sharedTCAttachment),
	}
	if monitor, monitorErr := tun.NewNetworkUpdateMonitor(log.SingLogger); monitorErr == nil {
		s.tcManager.networkMonitor = monitor
	}
	if err = s.tcManager.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	s.startUDPPeriodic()
	s.startFlowJanitor()
	log.Infoln("[EBPF] shared-network TC interception ready: downstream_interfaces=[%s], redirect_listener_port=%d, dns_mode=%s, ipv6_mode=%s, bypass_private_address=%v, data_plane=%s, udp_socket_assignment=%v, source_cidr={include:%d, exclude:%d}, tc_priority=%d, map_capacity=%d, programs=[tc/ingress, tc/egress]",
		s.tcManager.InterfaceString(),
		s.listeners.selectedPort(),
		s.inbound.dnsMode,
		s.inbound.sharedIPv6Mode,
		s.inbound.bypassPrivateAddress,
		s.sharedBackendInstance().DataPlane(),
		s.sharedBackendInstance().UDPAssignmentEnabled(),
		len(s.options.IncludeSourceCIDR),
		len(s.options.ExcludeSourceCIDR),
		s.tcPriority,
		s.mapCapacity,
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.redirectIPv6Prefix.IsValid(),
		s.newListener,
	)
}

func (s *sharedNetwork) newListener(network string, ipv6 bool, port uint16) (*internalListener, error) {
	return newInternalListener(s.inbound.socketControl(ipv6), network, ipv6, port, s)
}

func (s *sharedNetwork) startUDPPeriodic() {
	s.periodicStop = make(chan struct{})
	s.periodicDone = make(chan struct{})
	go s.udpPeriodicLoop(s.periodicStop, s.periodicDone)
}

func (s *sharedNetwork) stopUDPPeriodic() {
	if s.periodicStop == nil {
		return
	}
	close(s.periodicStop)
	<-s.periodicDone
	s.periodicStop = nil
}

func (s *sharedNetwork) udpPeriodicLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := s.inbound.udpTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.udpClientTable.sweep(time.Now(), s.inbound.udpTimeout, s.releaseFlows)
		}
	}
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpClientTable.sweep(time.Now(), 0, s.releaseFlows)
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	if manager := s.tcManager; manager != nil {
		manager.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	s.stopUDPPeriodic()
	s.stopFlowJanitor()
	if s.tcManager != nil {
		if err := s.tcManager.Close(); err != nil {
			return err
		}
		s.tcManager = nil
	}
	var backendErr error
	if backend := s.sharedBackendInstance(); backend != nil {
		backendErr = backend.Close()
		if backend.IsClosed() {
			s.setSharedBackend(nil)
		}
	}
	closeErr := E.Errors(backendErr, s.closeListeners())
	if s.policyRoute != nil {
		closeErr = E.Errors(closeErr, s.policyRoute.Close())
		s.policyRoute = nil
	}
	return closeErr
}

// startFlowJanitor keeps the shared proxy/flow maps healthy: it flushes
// released TCP flow slots on demand, watches token-reservation pressure and
// sweeps orphaned flows with a bounded scan budget (mirrors upstream).
func (s *sharedNetwork) startFlowJanitor() {
	s.janitorAccess.Lock()
	defer s.janitorAccess.Unlock()
	if s.janitorCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.janitorCancel = cancel
	s.janitorDone = done
	go s.runFlowJanitor(ctx, done)
}

func (s *sharedNetwork) stopFlowJanitor() {
	s.janitorAccess.Lock()
	if s.janitorCancel == nil {
		s.janitorAccess.Unlock()
		return
	}
	cancel := s.janitorCancel
	done := s.janitorDone
	s.janitorCancel = nil
	s.janitorDone = nil
	s.janitorAccess.Unlock()
	cancel()
	<-done
}

func sharedFlowSweepRequired(idle time.Duration, pressure bool, reservationPressure bool, scanInProgress bool) bool {
	if scanInProgress {
		return true
	}
	if pressure || reservationPressure {
		return idle >= sharedFlowPressureInterval
	}
	return idle >= sharedFlowSweepInterval
}

func (s *sharedNetwork) runFlowJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	pressureTicker := time.NewTicker(sharedFlowPressureInterval)
	defer pressureTicker.Stop()
	var releaseTimer *time.Timer
	var releaseTimerChannel <-chan time.Time
	resetReleaseTimer := func(backend *ECommon.SharedNetworkBackend) {
		delay, available := backend.NextTCPFlowReleaseDelay(time.Now())
		if !available {
			if releaseTimer != nil {
				releaseTimer.Stop()
			}
			releaseTimerChannel = nil
			return
		}
		if releaseTimer == nil {
			releaseTimer = time.NewTimer(delay)
		} else {
			if !releaseTimer.Stop() {
				select {
				case <-releaseTimer.C:
				default:
				}
			}
			releaseTimer.Reset(delay)
		}
		releaseTimerChannel = releaseTimer.C
	}
	defer func() {
		if releaseTimer != nil {
			releaseTimer.Stop()
		}
	}()
	pressure := false
	belowExitRounds := 0
	lastSweep := time.Now()
	var lastReservationFailures uint64
	scanInProgress := false
	attachmentActive := s.tcManager != nil && s.tcManager.isEnabled()
	for {
		backend := s.sharedBackendInstance()
		if backend == nil {
			return
		}
		pressurePoll := false
		select {
		case <-ctx.Done():
			return
		case <-pressureTicker.C:
			pressurePoll = true
		case <-backend.TCPFlowReleaseWake():
			resetReleaseTimer(backend)
			continue
		case <-releaseTimerChannel:
		}
		now := time.Now()
		if !pressurePoll {
			if _, flushErr := backend.FlushReleasedTCPFlows(now, sharedFlowReleaseFlushBudget); flushErr != nil {
				log.Debugln("[EBPF] flush released shared-network TCP flows: %s", flushErr.Error())
			}
			resetReleaseTimer(backend)
			continue
		}
		if s.tcManager == nil || !s.tcManager.isEnabled() {
			attachmentActive = false
			pressure = false
			belowExitRounds = 0
			scanInProgress = false
			continue
		}
		if !attachmentActive {
			attachmentActive = true
			lastSweep = time.Time{}
		}
		reservationPressure := false
		reservationFailures, failureErr := backend.TokenReservationFailures()
		if failureErr != nil {
			log.Debugln("[EBPF] read shared-network token reservation failures: %s", failureErr.Error())
		} else {
			reservationPressure = reservationFailures > lastReservationFailures
			lastReservationFailures = reservationFailures
		}
		if !sharedFlowSweepRequired(now.Sub(lastSweep), pressure, reservationPressure, scanInProgress) {
			continue
		}
		maxIdle := sharedFlowMaxIdle
		if pressure || reservationPressure {
			maxIdle = sharedFlowPressureMaxIdle
		}
		result, err := backend.SweepOrphanedFlows(maxIdle, sharedFlowFallbackScanBudget)
		if err != nil {
			if reservationPressure {
				pressure = true
			}
			log.Debugln("[EBPF] sweep orphaned shared-network flows: %s", err.Error())
		} else {
			scanInProgress = !result.Complete
			if result.Complete {
				lastSweep = now
			}
			usagePercent := 0
			if result.Usage.Capacity > 0 {
				usagePercent = int(result.Usage.Entries * 100 / result.Usage.Capacity)
			}
			switch {
			case usagePercent >= sharedFlowPressureEnterPercent:
				pressure = true
				belowExitRounds = 0
			case usagePercent <= sharedFlowPressureExitPercent && pressure:
				belowExitRounds++
				if belowExitRounds >= sharedFlowPressureExitRounds {
					pressure = false
					belowExitRounds = 0
				}
			default:
				belowExitRounds = 0
			}
			if result.Removed > 0 {
				log.Debugln("[EBPF] shared-network flow cleanup: removed=%d, usage=%d/%d",
					result.Removed, result.Usage.Entries, result.Usage.Capacity)
			}
		}
	}
}

func (s *sharedNetwork) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.tcManager == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedNetwork) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedNetwork) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}

func (s *sharedNetwork) acceptWarn(message ...any) {
	s.udpWarnings.accept.warn(s.inbound.logWarn, message...)
}

func (s *sharedNetwork) packetWarn(message ...any) {
	s.udpWarnings.packetInfo.warn(s.inbound.logWarn, message...)
}

var _ internalListenerHandler = (*sharedNetwork)(nil)
