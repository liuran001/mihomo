//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	sharedNetworkProgramIngress = iota
	sharedNetworkProgramEgress
	sharedNetworkProgramRewriteIngress
	sharedNetworkProgramCount
)

const (
	SharedNetworkDataPlaneAuto         = "auto"
	SharedNetworkDataPlaneSocketAssign = "socket_assign"
	SharedNetworkDataPlaneRewrite      = "rewrite"
)

type sharedNetworkRuntime struct {
	maps                        map[string]*CiliumEBPF.Map
	programs                    []*CiliumEBPF.Program
	control_map_fd              int
	stats_map_fd                int
	flow_by_original_map_fd     int
	bypass_flow_map_fd          int
	flow_by_token_map_fd        int
	fragment_map_fd             int
	host_ipv4_map_fd            int
	host_ipv6_map_fd            int
	include_source_ipv4_map_fd  int
	include_source_ipv6_map_fd  int
	exclude_source_ipv4_map_fd  int
	exclude_source_ipv6_map_fd  int
	include_source_mac_map_fd   int
	exclude_source_mac_map_fd   int
	fallback_bypass_ipv4_map_fd int
	fallback_bypass_ipv6_map_fd int
	scratch_map_fd              int
	listener_socket_map_fd      int
	assign_metadata_map_fd      int
	ingress_prog_fd             int
	egress_prog_fd              int
	data_plane                  string
	assignment_fallback_reason  string
	udp_assignment              bool
	udp_assignment_fallback     string
	non_common_lru              bool
}

type SharedNetworkBackend struct {
	access              sync.RWMutex
	health              backendHealth
	flowAccess          sync.Mutex
	replyTokenSequence  atomic.Uint64
	flowReferences      map[SharedNetworkFlowHandle]uint32
	flowReleases        map[SharedNetworkFlowHandle]time.Time
	flowReleaseWake     chan struct{}
	tokenLookupMisses   atomic.Uint64
	generationMisses    atomic.Uint64
	generationMismatch  atomic.Uint64
	flowSweepAccess     sync.Mutex
	flowSweepScratch    mapScanScratch[sharedNetworkOriginalKey, sharedNetworkTokenValue]
	flowSweepCandidates []sharedNetworkFlowEntry
	flowSweepRemoved    uint32
	proxyUsage          atomic.Uint32
	proxyUsageKnown     atomic.Bool
	statusCollector     runtimeStatusCollector
	runtime             *sharedNetworkRuntime
	statsMapFD          int
	mapCapacity         SharedNetworkMapCapacities
	control             sharedNetworkControl
	hostIPv4            []netip.Prefix
	hostIPv6            []netip.Prefix
	bypassIPv4Map       *CiliumEBPF.Map
	bypassIPv6Map       *CiliumEBPF.Map
	bypassIPv4MapFD     int
	bypassIPv6MapFD     int
	bypassIPv4CIDR      []netip.Prefix
	bypassIPv6CIDR      []netip.Prefix
	bypassIPv4Count     int
	bypassIPv6Count     int
	includeSourceIPv4   []netip.Prefix
	includeSourceIPv6   []netip.Prefix
	excludeSourceIPv4   []netip.Prefix
	excludeSourceIPv6   []netip.Prefix
	includeSourceMAC    []MACAddress
	excludeSourceMAC    []MACAddress
}

func PrepareSharedNetwork(cgroupBackend *CgroupBackend, config SharedNetworkConfig) (*SharedNetworkBackend, error) {
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	fakeIPIPv4, err := normalizeAddressPrefix("IPv4 FakeIP range", config.FakeIPIPv4, true)
	if err != nil {
		return nil, err
	}
	fakeIPIPv6, err := normalizeAddressPrefix("IPv6 FakeIP range", config.FakeIPIPv6, false)
	if err != nil {
		return nil, err
	}
	for name, capacity := range map[string]uint32{
		"shared-network proxy":    config.MapCapacity.Proxy,
		"shared-network bypass":   config.MapCapacity.Bypass,
		"shared-network fragment": config.MapCapacity.Fragment,
	} {
		if err := validateMapCapacity(name, capacity); err != nil {
			return nil, err
		}
	}
	if len(config.IncludeSourceMAC) > maxSharedSourceMACPolicyEntries ||
		len(config.ExcludeSourceMAC) > maxSharedSourceMACPolicyEntries {
		return nil, E.New("shared-network source MAC policy exceeds eBPF map capacity")
	}
	if config.ListenerPort == 0 {
		return nil, E.New("missing shared-network listener port")
	}
	udpTimeoutSeconds, err := sharedNetworkUDPTimeoutSeconds(config.UDPTimeout)
	if err != nil {
		return nil, err
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing shared-network redirect address")
	}
	memlockErr := raiseMemlockLimit()
	if err := checkKernelCapabilities("shared-network", ""); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}

	runtimeState := &sharedNetworkRuntime{
		maps:                        make(map[string]*CiliumEBPF.Map),
		programs:                    make([]*CiliumEBPF.Program, sharedNetworkProgramCount),
		fallback_bypass_ipv4_map_fd: -1,
		fallback_bypass_ipv6_map_fd: -1,
		ingress_prog_fd:             -1,
		egress_prog_fd:              -1,
		listener_socket_map_fd:      -1,
		assign_metadata_map_fd:      -1,
		non_common_lru:              probeNonCommonLRU(),
	}
	var bypassIPv4Map *CiliumEBPF.Map
	var bypassIPv6Map *CiliumEBPF.Map
	if cgroupBackend != nil {
		cgroupBackend.access.RLock()
		if err := cgroupBackend.health.requireUsable(cgroupBackend.runtime != nil); err != nil {
			cgroupBackend.access.RUnlock()
			return nil, err
		}
		bypassIPv4Map = cgroupBackend.runtime.maps["cgroup_bypass_ipv4"]
		bypassIPv6Map = cgroupBackend.runtime.maps["cgroup_bypass_ipv6"]
	}
	err = prepareSharedNetworkRuntime(
		runtimeState,
		config.MapCapacity,
		len(config.IncludeSourceMAC),
		len(config.ExcludeSourceMAC),
		bypassIPv4Map,
		bypassIPv6Map,
		config.DataPlane,
	)
	if cgroupBackend != nil {
		cgroupBackend.access.RUnlock()
	}
	if err != nil {
		_ = closePrograms(runtimeState.programs)
		_ = closeMaps(runtimeState.maps)
		prepareErr := eBPFBackendOperationError(
			"prepare shared-network programs",
			verifierErrorStage(err),
			err,
		)
		if memlockErr != nil && (errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EPERM)) {
			prepareErr = E.Errors(prepareErr, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, prepareErr
	}
	if bypassIPv4Map == nil {
		bypassIPv4Map = runtimeState.maps["shared_bypass_ipv4"]
	}
	if bypassIPv6Map == nil {
		bypassIPv6Map = runtimeState.maps["shared_bypass_ipv6"]
	}

	bypassIPv4MapFD := runtimeState.fallback_bypass_ipv4_map_fd
	bypassIPv6MapFD := runtimeState.fallback_bypass_ipv6_map_fd
	if bypassIPv4Map != nil {
		bypassIPv4MapFD = bypassIPv4Map.FD()
	}
	if bypassIPv6Map != nil {
		bypassIPv6MapFD = bypassIPv6Map.FD()
	}
	backend := &SharedNetworkBackend{
		mapCapacity:     config.MapCapacity,
		runtime:         runtimeState,
		statsMapFD:      runtimeState.stats_map_fd,
		bypassIPv4Map:   bypassIPv4Map,
		bypassIPv6Map:   bypassIPv6Map,
		bypassIPv4MapFD: bypassIPv4MapFD,
		bypassIPv6MapFD: bypassIPv6MapFD,
		flowReleaseWake: make(chan struct{}, 1),
	}
	backend.control.ListenerPort = config.ListenerPort
	backend.control.DNSMode = config.DNSMode
	backend.control.UDPTimeoutSeconds = udpTimeoutSeconds
	backend.control.RoutingMark = config.RoutingMark
	if runtimeState.data_plane == SharedNetworkDataPlaneSocketAssign {
		backend.control.Flags |= sharedNetworkFlagSocketAssignTCP
		if runtimeState.udp_assignment && config.EnableUDP {
			backend.control.Flags |= sharedNetworkFlagSocketAssignUDP
		}
	}
	if config.EnableTCP {
		backend.control.Flags |= sharedNetworkFlagTCP
	}
	if config.EnableUDP {
		backend.control.Flags |= sharedNetworkFlagUDP
	}
	if config.BypassPrivateAddress {
		backend.control.Flags |= sharedNetworkFlagBypassPrivateAddress
	}
	if redirectIPv4.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv4
		backend.control.TokenIPv4Prefix = redirectIPv4.Addr().As4()
		backend.control.TokenIPv4PrefixBits = uint8(redirectIPv4.Bits())
	}
	if redirectIPv6.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv6
		backend.control.TokenIPv6Prefix = redirectIPv6.Addr().As16()
		backend.control.TokenIPv6PrefixBits = uint8(redirectIPv6.Bits())
	}
	if fakeIPIPv4.IsValid() {
		backend.control.Flags |= sharedNetworkFlagFakeIPIPv4
		backend.control.FakeIPIPv4Prefix = fakeIPIPv4.Addr().As4()
		backend.control.FakeIPIPv4Mask = prefixMask4(fakeIPIPv4.Bits())
	}
	if fakeIPIPv6.IsValid() {
		backend.control.Flags |= sharedNetworkFlagFakeIPIPv6
		backend.control.FakeIPIPv6Prefix = fakeIPIPv6.Addr().As16()
		backend.control.FakeIPIPv6Mask = prefixMask16(fakeIPIPv6.Bits())
	}
	if err = backend.initializeSourceCIDRPolicy(config.IncludeSourceCIDR, config.ExcludeSourceCIDR); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err = backend.initializeSourceMACPolicy(config.IncludeSourceMAC, config.ExcludeSourceMAC); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err := backend.updateControl(); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "initialize shared-network control")
	}
	return backend, nil
}

func prepareSharedNetworkRuntime(
	runtimeState *sharedNetworkRuntime,
	capacity SharedNetworkMapCapacities,
	includeSourceMACEntries int,
	excludeSourceMACEntries int,
	bypassIPv4Map *CiliumEBPF.Map,
	bypassIPv6Map *CiliumEBPF.Map,
	dataPlane string,
) error {
	cacheLRUFlags := uint32(0)
	if runtimeState.non_common_lru {
		cacheLRUFlags = unix.BPF_F_NO_COMMON_LRU
	}
	var err error
	runtimeState.maps, err = loadObjectMaps(loadSharedNetwork, map[string]mapSpecOverride{
		"shared_control":             {name: "sb_sh_control", mapType: CiliumEBPF.Array, maxEntries: 1},
		"shared_stats":               {name: "sb_sh_stats", mapType: CiliumEBPF.PerCPUArray, maxEntries: 8},
		"shared_flow_by_original":    {name: "sb_sh_orig", mapType: CiliumEBPF.Hash, maxEntries: capacity.Proxy, flags: bpfFlagNoPrealloc},
		"shared_bypass_flow":         {name: "sb_sh_bypass", mapType: CiliumEBPF.LRUHash, maxEntries: capacity.Bypass, flags: cacheLRUFlags},
		"shared_flow_by_token":       {name: "sb_sh_token", mapType: CiliumEBPF.Hash, maxEntries: capacity.Proxy, flags: bpfFlagNoPrealloc},
		"shared_fragment":            {name: "sb_sh_fragment", mapType: CiliumEBPF.LRUHash, maxEntries: capacity.Fragment, flags: cacheLRUFlags},
		"shared_host_ipv4":           {name: "sb_sh_host4", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries, flags: bpfFlagNoPrealloc},
		"shared_host_ipv6":           {name: "sb_sh_host6", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries, flags: bpfFlagNoPrealloc},
		"shared_include_source_ipv4": {name: "sb_sh_inc4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxSharedSourceCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"shared_include_source_ipv6": {name: "sb_sh_inc6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxSharedSourceCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"shared_exclude_source_ipv4": {name: "sb_sh_exc4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxSharedSourceCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"shared_exclude_source_ipv6": {name: "sb_sh_exc6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxSharedSourceCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"shared_include_source_mac":  {name: "sb_sh_inmac", mapType: CiliumEBPF.Hash, maxEntries: sharedSourceMACMapCapacity(includeSourceMACEntries)},
		"shared_exclude_source_mac":  {name: "sb_sh_exmac", mapType: CiliumEBPF.Hash, maxEntries: sharedSourceMACMapCapacity(excludeSourceMACEntries)},
		"shared_scratch":             {name: "sb_sh_scratch", mapType: CiliumEBPF.PerCPUArray, maxEntries: 1},
	})
	if err != nil {
		return err
	}
	if bypassIPv4Map == nil {
		if err := createSharedBypassMap(runtimeState, "shared_bypass_ipv4", "sb_sh_bypass4"); err != nil {
			return err
		}
		bypassIPv4Map = runtimeState.maps["shared_bypass_ipv4"]
		runtimeState.fallback_bypass_ipv4_map_fd = bypassIPv4Map.FD()
	}
	if bypassIPv6Map == nil {
		if err := createSharedBypassMap(runtimeState, "shared_bypass_ipv6", "sb_sh_bypass6"); err != nil {
			return err
		}
		bypassIPv6Map = runtimeState.maps["shared_bypass_ipv6"]
		runtimeState.fallback_bypass_ipv6_map_fd = bypassIPv6Map.FD()
	}
	replacements := make(map[string]*CiliumEBPF.Map, len(runtimeState.maps)+2)
	for name, mapInstance := range runtimeState.maps {
		replacements[name] = mapInstance
	}
	replacements["shared_bypass_ipv4"] = bypassIPv4Map
	replacements["shared_bypass_ipv6"] = bypassIPv6Map
	wantAssignment := dataPlane != SharedNetworkDataPlaneRewrite
	if wantAssignment {
		listenerMap, listenerErr := newRuntimeMap("sb_sh_listen", CiliumEBPF.SockMap, 4, 4, 2, 0)
		if listenerErr == nil {
			runtimeState.maps["shared_listener_sockets"] = listenerMap
			replacements["shared_listener_sockets"] = listenerMap
			metadataMap, metadataErr := newRuntimeMap(
				"sb_sh_assign", CiliumEBPF.LRUHash, 40, 12, capacity.Proxy, 0,
			)
			if metadataErr == nil {
				runtimeState.maps["shared_assign_metadata"] = metadataMap
				replacements["shared_assign_metadata"] = metadataMap
				assignmentSection := "classifier/assign"
				assignmentName := "sb_sh_assign"
				if dataPlane == SharedNetworkDataPlaneSocketAssign {
					assignmentSection = "classifier/assign_udp"
					assignmentName = "sb_sh_as_udp"
				}
				programs, programErr := loadObjectPrograms(loadSharedNetwork, replacements, []programSelection{
					{section: assignmentSection, name: assignmentName},
					{section: "classifier/egress", name: "sb_share_out"},
					{section: "classifier/ingress", name: "sb_share_in"},
				})
				if programErr == nil && dataPlane == SharedNetworkDataPlaneSocketAssign {
					runtimeState.udp_assignment = true
				} else if programErr != nil && dataPlane == SharedNetworkDataPlaneSocketAssign {
					runtimeState.udp_assignment_fallback = programErr.Error()
					programs, programErr = loadObjectPrograms(loadSharedNetwork, replacements, []programSelection{
						{section: "classifier/assign", name: "sb_sh_assign"},
						{section: "classifier/egress", name: "sb_share_out"},
						{section: "classifier/ingress", name: "sb_share_in"},
					})
				}
				if programErr == nil {
					runtimeState.programs = programs
					runtimeState.data_plane = SharedNetworkDataPlaneSocketAssign
				} else {
					runtimeState.assignment_fallback_reason = programErr.Error()
				}
			} else {
				runtimeState.assignment_fallback_reason = metadataErr.Error()
			}
		} else {
			runtimeState.assignment_fallback_reason = listenerErr.Error()
		}
		if runtimeState.data_plane != SharedNetworkDataPlaneSocketAssign {
			if dataPlane == SharedNetworkDataPlaneSocketAssign {
				return E.New("shared-network socket assignment is unavailable: ", runtimeState.assignment_fallback_reason)
			}
			if listener := runtimeState.maps["shared_listener_sockets"]; listener != nil {
				_ = listener.Close()
				delete(runtimeState.maps, "shared_listener_sockets")
				delete(replacements, "shared_listener_sockets")
			}
			if metadata := runtimeState.maps["shared_assign_metadata"]; metadata != nil {
				_ = metadata.Close()
				delete(runtimeState.maps, "shared_assign_metadata")
				delete(replacements, "shared_assign_metadata")
			}
		}
	}
	if runtimeState.data_plane == "" {
		programs, loadErr := loadObjectPrograms(loadSharedNetwork, replacements, []programSelection{
			{section: "classifier/ingress", name: "sb_share_in"},
			{section: "classifier/egress", name: "sb_share_out"},
		})
		if loadErr != nil {
			return loadErr
		}
		runtimeState.programs = make([]*CiliumEBPF.Program, sharedNetworkProgramCount)
		runtimeState.programs[sharedNetworkProgramIngress] = programs[0]
		runtimeState.programs[sharedNetworkProgramEgress] = programs[1]
		runtimeState.data_plane = SharedNetworkDataPlaneRewrite
	}
	runtimeState.control_map_fd = runtimeState.maps["shared_control"].FD()
	runtimeState.stats_map_fd = runtimeState.maps["shared_stats"].FD()
	runtimeState.flow_by_original_map_fd = runtimeState.maps["shared_flow_by_original"].FD()
	runtimeState.bypass_flow_map_fd = runtimeState.maps["shared_bypass_flow"].FD()
	runtimeState.flow_by_token_map_fd = runtimeState.maps["shared_flow_by_token"].FD()
	runtimeState.fragment_map_fd = runtimeState.maps["shared_fragment"].FD()
	runtimeState.host_ipv4_map_fd = runtimeState.maps["shared_host_ipv4"].FD()
	runtimeState.host_ipv6_map_fd = runtimeState.maps["shared_host_ipv6"].FD()
	runtimeState.include_source_ipv4_map_fd = runtimeState.maps["shared_include_source_ipv4"].FD()
	runtimeState.include_source_ipv6_map_fd = runtimeState.maps["shared_include_source_ipv6"].FD()
	runtimeState.exclude_source_ipv4_map_fd = runtimeState.maps["shared_exclude_source_ipv4"].FD()
	runtimeState.exclude_source_ipv6_map_fd = runtimeState.maps["shared_exclude_source_ipv6"].FD()
	runtimeState.include_source_mac_map_fd = runtimeState.maps["shared_include_source_mac"].FD()
	runtimeState.exclude_source_mac_map_fd = runtimeState.maps["shared_exclude_source_mac"].FD()
	runtimeState.scratch_map_fd = runtimeState.maps["shared_scratch"].FD()
	if listenerMap := runtimeState.maps["shared_listener_sockets"]; listenerMap != nil {
		runtimeState.listener_socket_map_fd = listenerMap.FD()
	}
	if metadataMap := runtimeState.maps["shared_assign_metadata"]; metadataMap != nil {
		runtimeState.assign_metadata_map_fd = metadataMap.FD()
	}
	runtimeState.ingress_prog_fd = runtimeState.programs[sharedNetworkProgramIngress].FD()
	runtimeState.egress_prog_fd = runtimeState.programs[sharedNetworkProgramEgress].FD()
	return nil
}

func sharedSourceMACMapCapacity(entries int) uint32 {
	if entries <= 0 {
		return 1
	}
	return uint32(entries)
}

func createSharedBypassMap(runtimeState *sharedNetworkRuntime, objectName string, kernelName string) error {
	maps, err := loadObjectMaps(loadSharedNetwork, map[string]mapSpecOverride{
		objectName: {name: kernelName, mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
	})
	if err != nil {
		return err
	}
	runtimeState.maps[objectName] = maps[objectName]
	return nil
}

func (b *SharedNetworkBackend) updateControl() error {
	if b == nil || b.runtime == nil {
		return errBackendClosed
	}
	key := uint32(0)
	return updateMap(
		b.runtime.control_map_fd,
		unsafe.Pointer(&key),
		unsafe.Pointer(&b.control),
	)
}

func (b *SharedNetworkBackend) Enable() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	previous := b.control.Enabled
	b.control.Enabled = 1
	if err := b.updateControl(); err != nil {
		b.control.Enabled = previous
		return err
	}
	return nil
}

func (b *SharedNetworkBackend) requireUsableLocked() error {
	return b.health.requireUsable(b.runtime != nil)
}

func (b *SharedNetworkBackend) invalidateLocked(operation string, cause error) error {
	rebuildRequired := b.health.invalidate("shared-network", operation)
	b.control.Enabled = 0
	disableErr := b.updateControl()
	if disableErr != nil {
		disableErr = E.Cause(disableErr, "disable unusable shared-network backend")
	}
	return E.Errors(
		cause,
		disableErr,
		rebuildRequired,
	)
}

func (b *SharedNetworkBackend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	previous := b.control.Enabled
	b.control.Enabled = 0
	if err := b.updateControl(); err != nil {
		b.control.Enabled = previous
		return err
	}
	return nil
}

func (b *SharedNetworkBackend) IngressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return b.runtime.ingress_prog_fd
}

func (b *SharedNetworkBackend) DataPlane() string {
	if b == nil {
		return SharedNetworkDataPlaneRewrite
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.data_plane == "" {
		return SharedNetworkDataPlaneRewrite
	}
	return b.runtime.data_plane
}

func (b *SharedNetworkBackend) TCPAssignmentEnabled() bool {
	return b.DataPlane() == SharedNetworkDataPlaneSocketAssign
}

func (b *SharedNetworkBackend) UDPAssignmentEnabled() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime != nil && b.runtime.data_plane == SharedNetworkDataPlaneSocketAssign && b.runtime.udp_assignment
}

func (b *SharedNetworkBackend) UDPAssignmentFallbackReason() string {
	if b == nil {
		return ""
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return ""
	}
	return b.runtime.udp_assignment_fallback
}

func (b *SharedNetworkBackend) AssignmentFallbackReason() string {
	if b == nil {
		return ""
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return ""
	}
	return b.runtime.assignment_fallback_reason
}

func (b *SharedNetworkBackend) RegisterTCPAssignmentSocket(key uint32, fd int) error {
	if b == nil || key >= 2 || fd < 0 {
		return E.New("invalid shared-network TCP assignment listener")
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.listener_socket_map_fd < 0 {
		return errBackendClosed
	}
	value := uint32(fd)
	return updateMap(
		b.runtime.listener_socket_map_fd,
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	)
}

func (b *SharedNetworkBackend) FallbackToRewrite() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	if b.runtime.data_plane != SharedNetworkDataPlaneSocketAssign {
		return nil
	}
	rewrite := b.runtime.programs[sharedNetworkProgramRewriteIngress]
	if rewrite == nil {
		return E.New("shared-network rewrite fallback program is unavailable")
	}
	assignment := b.runtime.programs[sharedNetworkProgramIngress]
	b.runtime.programs[sharedNetworkProgramIngress] = rewrite
	b.runtime.programs[sharedNetworkProgramRewriteIngress] = nil
	if assignment != nil {
		_ = assignment.Close()
	}
	b.runtime.ingress_prog_fd = rewrite.FD()
	b.runtime.data_plane = SharedNetworkDataPlaneRewrite
	b.control.Flags &^= sharedNetworkFlagSocketAssignTCP
	b.control.Flags &^= sharedNetworkFlagSocketAssignUDP
	b.control.RoutingMark = 0
	return b.updateControl()
}

func (b *SharedNetworkBackend) TakeTCPAssignmentMetadata(
	client netip.AddrPort,
	destination netip.AddrPort,
) (uint32, MACAddress, error) {
	var sourceMAC MACAddress
	key, err := makeSharedNetworkAssignKey(ProtocolTCP, client, destination)
	if err != nil {
		return 0, sourceMAC, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.assign_metadata_map_fd < 0 {
		return 0, sourceMAC, errBackendClosed
	}
	var value sharedNetworkAssignValue
	if err = lookupAndDeleteMap(
		b.runtime.assign_metadata_map_fd,
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return 0, sourceMAC, err
	}
	copy(sourceMAC[:], value.SourceMAC[:])
	return value.InterfaceIndex, sourceMAC, nil
}

func (b *SharedNetworkBackend) LookupUDPAssignmentMetadata(
	client netip.AddrPort,
	destination netip.AddrPort,
) (uint32, MACAddress, error) {
	var sourceMAC MACAddress
	key, err := makeSharedNetworkAssignKey(ProtocolUDP, client, destination)
	if err != nil {
		return 0, sourceMAC, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.assign_metadata_map_fd < 0 {
		return 0, sourceMAC, errBackendClosed
	}
	var value sharedNetworkAssignValue
	if err = lookupMap(
		b.runtime.assign_metadata_map_fd,
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return 0, sourceMAC, err
	}
	copy(sourceMAC[:], value.SourceMAC[:])
	return value.InterfaceIndex, sourceMAC, nil
}

func (b *SharedNetworkBackend) EgressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return b.runtime.egress_prog_fd
}

func (b *SharedNetworkBackend) IngressProgramIdentity() (int, string) {
	return b.programIdentity(sharedNetworkProgramIngress)
}

func (b *SharedNetworkBackend) EgressProgramIdentity() (int, string) {
	return b.programIdentity(sharedNetworkProgramEgress)
}

func (b *SharedNetworkBackend) programIdentity(index int) (int, string) {
	if b == nil {
		return 0, ""
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || index < 0 || index >= len(b.runtime.programs) || b.runtime.programs[index] == nil {
		return 0, ""
	}
	info, err := b.runtime.programs[index].Info()
	if err != nil {
		return 0, ""
	}
	id, ok := info.ID()
	if !ok {
		return 0, info.Tag
	}
	return int(id), info.Tag
}

func (b *SharedNetworkBackend) RuntimeStatus() SharedNetworkRuntimeStatus {
	if b == nil {
		return SharedNetworkRuntimeStatus{}
	}
	b.access.RLock()
	if b.runtime == nil {
		b.access.RUnlock()
		return SharedNetworkRuntimeStatus{}
	}
	status := SharedNetworkRuntimeStatus{
		DataPlane:                   b.runtime.data_plane,
		NonCommonLRU:                b.runtime.non_common_lru,
		UDPAssignment:               b.runtime.udp_assignment,
		UDPAssignmentFallbackReason: b.runtime.udp_assignment_fallback,
		Maps:                        b.statusCollector.collect(b.runtime.maps),
	}
	for slot, program := range b.runtime.programs {
		if program == nil {
			continue
		}
		name := "sb_share_in"
		section := "classifier/ingress"
		if slot == sharedNetworkProgramIngress && b.runtime.data_plane == SharedNetworkDataPlaneSocketAssign {
			name = "sb_sh_assign"
			section = "classifier/assign"
			if b.runtime.udp_assignment {
				name = "sb_sh_as_udp"
				section = "classifier/assign_udp"
			}
		}
		if slot == sharedNetworkProgramEgress {
			name = "sb_share_out"
			section = "classifier/egress"
		} else if slot == sharedNetworkProgramRewriteIngress {
			name = "sb_share_fallback"
		}
		status.Programs = append(status.Programs, runtimeProgramStatus(program, name, section))
	}
	b.access.RUnlock()
	var statsErr error
	status.Statistics, statsErr = b.SharedNetworkStatistics()
	if statsErr != nil {
		status.StatsError = statsErr.Error()
	}
	return status
}

func (b *SharedNetworkBackend) MapCapacity() SharedNetworkMapCapacities {
	if b == nil {
		return SharedNetworkMapCapacities{}
	}
	return b.mapCapacity
}

func (b *SharedNetworkBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	b.control.Enabled = 0
	_ = b.updateControl()
	closeErr := closePrograms(b.runtime.programs)
	closeErr = E.Errors(closeErr, closeMaps(b.runtime.maps))
	b.runtime = nil
	b.hostIPv4 = nil
	b.hostIPv6 = nil
	b.bypassIPv4Map = nil
	b.bypassIPv6Map = nil
	b.bypassIPv4MapFD = -1
	b.bypassIPv6MapFD = -1
	b.bypassIPv4CIDR = nil
	b.bypassIPv6CIDR = nil
	b.includeSourceIPv4 = nil
	b.includeSourceIPv6 = nil
	b.excludeSourceIPv4 = nil
	b.excludeSourceIPv6 = nil
	b.includeSourceMAC = nil
	b.excludeSourceMAC = nil
	clear(b.flowReferences)
	return closeErr
}

func (b *SharedNetworkBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
