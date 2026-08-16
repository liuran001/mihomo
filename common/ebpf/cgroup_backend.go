//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	cgroupProgramConnect4 = iota
	cgroupProgramUDP4Sendmsg
	cgroupProgramUDP4Recvmsg
	cgroupProgramConnect6
	cgroupProgramUDP6Sendmsg
	cgroupProgramUDP6Recvmsg
	cgroupProgramSocketRelease
	cgroupProgramCount
)

type cgroupProgramDefinition struct {
	name       string
	attachType CiliumEBPF.AttachType
}

var cgroupProgramDefinitions = [cgroupProgramCount]cgroupProgramDefinition{
	{name: "sb_ebpf_conn4", attachType: CiliumEBPF.AttachCGroupInet4Connect},
	{name: "sb_ebpf_udp4", attachType: CiliumEBPF.AttachCGroupUDP4Sendmsg},
	{name: "sb_ebpf_urcv4", attachType: CiliumEBPF.AttachCGroupUDP4Recvmsg},
	{name: "sb_ebpf_conn6", attachType: CiliumEBPF.AttachCGroupInet6Connect},
	{name: "sb_ebpf_udp6", attachType: CiliumEBPF.AttachCGroupUDP6Sendmsg},
	{name: "sb_ebpf_urcv6", attachType: CiliumEBPF.AttachCGroupUDP6Recvmsg},
	{name: "sb_ebpf_rel", attachType: CiliumEBPF.AttachCgroupInetSockRelease},
}

type cgroupRuntime struct {
	cgroupFile                  *os.File
	maps                        map[string]*CiliumEBPF.Map
	programs                    []*CiliumEBPF.Program
	attached                    [cgroupProgramCount]bool
	control_map_fd              int
	stats_map_fd                int
	tcp_redirect_map_fd         int
	udp_redirect_map_fd         int
	udp_token_map_fd            int
	udp_peer_map_fd             int
	udp_flow_map_fd             int
	bypass_socket_cookie_map_fd int
	uid_policy_map_fd           int
	bypass_ipv4_cidr_map_fd     int
	bypass_ipv6_cidr_map_fd     int
	ipv6_available_map_fd       int
	socket_release_supported    bool
	self_bypass_tgid            bool
	enable_tcp                  bool
	enable_udp                  bool
	uid_policy                  bool
	uid_default_bypass          bool
	bypass_ipv4_policy          bool
	bypass_ipv6_policy          bool
	auto_ipv6                   bool
	socket_bypass_capacity      uint32
}

type CgroupBackend struct {
	access                sync.RWMutex
	health                backendHealth
	tcpSweepAccess        sync.Mutex
	tcpSweepScratch       mapScanScratch[listenerLookupKey, originalDestinationValue]
	tcpSweepCandidates    []tcpRedirectEntry
	tcpRedirectUsage      atomic.Uint32
	tcpRedirectUsageKnown atomic.Bool
	lookupAndDeleteMode   atomic.Int32
	selfBypassTGID        atomic.Bool
	runtime               *cgroupRuntime
	statsMapFD            int
	mapCapacity           CgroupMapCapacity
	tcpRedirectMapFD      int
	udpRedirectMapFD      int
	udpFlowMapFD          int
	socketBypassMapFD     int
	pendingSocketCookies  map[uint64]struct{}
	bypassIPv4CIDRMapFD   int
	bypassIPv6CIDRMapFD   int
	ipv6AvailableMapFD    int
	bypassIPv4CIDR        []netip.Prefix
	bypassIPv6CIDR        []netip.Prefix
	cgroupPath            string
	redirectIPv4          netip.Prefix
	redirectIPv6          netip.Prefix
	enableIPv6            bool
	autoIPv6              bool
	ipv6Available         bool
	enableUDP             bool
	hijackDNS             bool
	bypassPrivateAddress  bool
	dnsRespectBypass      bool
	udpTimeoutSeconds     uint32
}

func PrepareCgroup(config CgroupConfig) (*CgroupBackend, error) {
	cgroupPath := config.Path
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	mapCapacity := config.MapCapacity
	policy := config.Policy
	if err := validateCgroupMapCapacity(mapCapacity); err != nil {
		return nil, err
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if !redirectIPv4.Addr().Is4() {
			return nil, E.New("invalid IPv4 eBPF redirect address: ", redirectIPv4)
		}
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if !redirectIPv6.Addr().Is6() || redirectIPv6.Addr().Is4In6() {
			return nil, E.New("invalid IPv6 eBPF redirect address: ", redirectIPv6)
		}
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing eBPF redirect address")
	}
	if config.EnableIPv6 && !redirectIPv6.IsValid() {
		return nil, E.New("missing IPv6 eBPF redirect address")
	}
	if config.AutoIPv6 && !config.EnableIPv6 {
		return nil, E.New("automatic IPv6 interception requires enabled IPv6 interception")
	}
	if !redirectIPv4.IsValid() && !config.EnableIPv6 {
		return nil, E.New("eBPF cgroup backend has no enabled address family")
	}
	udpTimeoutSeconds := uint32(0)
	var err error
	if config.EnableUDP {
		udpTimeoutSeconds, err = cgroupUDPTimeoutSeconds(config.UDPTimeout)
		if err != nil {
			return nil, err
		}
	}
	uidPolicyEntries, uidDefaultBypass, err := compileUIDPolicy(policy)
	if err != nil {
		return nil, err
	}
	if err = checkLPMTriePolicyCompatibility("UID", len(uidPolicyEntries)); err != nil {
		return nil, err
	}
	if cgroupPath == "" {
		cgroupPath, err = DetectCgroup2Mount()
		if err != nil {
			return nil, err
		}
	}
	memlockErr := raiseMemlockLimit()
	if err = checkKernelCapabilities("cgroup", cgroupPath); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	socketReleaseSupported, err := probeSocketReleaseSupport()
	if err != nil {
		return nil, eBPFOperationError("probe socket release", err)
	}
	runtimeState := &cgroupRuntime{
		maps:                        make(map[string]*CiliumEBPF.Map),
		programs:                    make([]*CiliumEBPF.Program, cgroupProgramCount),
		enable_tcp:                  config.EnableTCP,
		enable_udp:                  config.EnableUDP,
		uid_policy:                  len(uidPolicyEntries) > 0 || uidDefaultBypass,
		uid_default_bypass:          uidDefaultBypass,
		bypass_ipv4_policy:          policy.EnableBypassCIDR && redirectIPv4.IsValid(),
		bypass_ipv6_policy:          policy.EnableBypassCIDR && redirectIPv6.IsValid(),
		auto_ipv6:                   config.AutoIPv6,
		socket_release_supported:    socketReleaseSupported,
		socket_bypass_capacity:      mapCapacity.SocketBypass,
		bypass_socket_cookie_map_fd: -1,
	}
	if err = prepareCgroupMaps(runtimeState, mapCapacity, len(uidPolicyEntries)); err != nil {
		_ = closeMaps(runtimeState.maps)
		if memlockErr != nil && (errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EPERM)) {
			err = E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	runtimeState.cgroupFile, err = os.Open(cgroupPath)
	if err != nil {
		_ = closeMaps(runtimeState.maps)
		return nil, eBPFOperationError("open cgroup", err)
	}
	if err = unix.Flock(int(runtimeState.cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = runtimeState.cgroupFile.Close()
		_ = closeMaps(runtimeState.maps)
		if errors.Is(err, unix.EWOULDBLOCK) {
			err = unix.EBUSY
		}
		return nil, eBPFOperationError("lock cgroup", err)
	}
	if err = detachOwnedCgroupPrograms(int(runtimeState.cgroupFile.Fd())); err != nil {
		_ = runtimeState.cgroupFile.Close()
		_ = closeMaps(runtimeState.maps)
		return nil, eBPFOperationError("detach stale cgroup programs", err)
	}
	backend := &CgroupBackend{
		mapCapacity:          mapCapacity,
		runtime:              runtimeState,
		tcpRedirectMapFD:     runtimeState.tcp_redirect_map_fd,
		statsMapFD:           runtimeState.stats_map_fd,
		udpRedirectMapFD:     runtimeState.udp_redirect_map_fd,
		udpFlowMapFD:         runtimeState.udp_flow_map_fd,
		socketBypassMapFD:    -1,
		bypassIPv4CIDRMapFD:  runtimeState.bypass_ipv4_cidr_map_fd,
		bypassIPv6CIDRMapFD:  runtimeState.bypass_ipv6_cidr_map_fd,
		ipv6AvailableMapFD:   runtimeState.ipv6_available_map_fd,
		cgroupPath:           cgroupPath,
		redirectIPv4:         redirectIPv4,
		redirectIPv6:         redirectIPv6,
		enableIPv6:           config.EnableIPv6,
		autoIPv6:             config.AutoIPv6,
		enableUDP:            config.EnableUDP,
		hijackDNS:            policy.HijackDNS,
		bypassPrivateAddress: policy.BypassPrivateAddress,
		dnsRespectBypass:     policy.DNSRespectBypass,
		udpTimeoutSeconds:    udpTimeoutSeconds,
	}
	if config.AutoIPv6 {
		if _, err = backend.updateIPv6AvailableLocked(config.IPv6Available); err != nil {
			_ = backend.Close()
			return nil, E.Cause(err, "initialize IPv6 availability eBPF map")
		}
	}
	if err = populateUIDPolicyMap(runtimeState.uid_policy_map_fd, uidPolicyEntries); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "populate UID policy eBPF map")
	}
	return backend, nil
}

func prepareCgroupMaps(runtimeState *cgroupRuntime, capacity CgroupMapCapacity, uidEntries int) error {
	udpMapType := CiliumEBPF.Hash
	udpMapFlags := uint32(bpfFlagNoPrealloc)
	if runtimeState.enable_udp && !runtimeState.socket_release_supported {
		udpMapType = CiliumEBPF.LRUHash
		udpMapFlags = 0
	}
	tcpCapacity := uint32(1)
	udpCapacity := uint32(1)
	if runtimeState.enable_tcp {
		tcpCapacity = capacity.TCPRedirect
	}
	if runtimeState.enable_udp {
		udpCapacity = capacity.UDPRedirect
	}
	flowCapacity := uint32(1)
	if runtimeState.enable_udp && runtimeState.socket_release_supported {
		flowCapacity = udpCapacity
	}
	uidCapacity := uint32(uidEntries)
	if uidCapacity == 0 {
		uidCapacity = 1
	}
	var err error
	runtimeState.maps, err = loadObjectMaps(loadCgroup, map[string]mapSpecOverride{
		"cgroup_control":        {name: "sb_cg_control", mapType: CiliumEBPF.Array, maxEntries: 1},
		"cgroup_stats":          {name: "sb_cg_stats", mapType: CiliumEBPF.Array, maxEntries: 2},
		"cgroup_tcp_redirect":   {name: "sb_cg_tcp", mapType: CiliumEBPF.Hash, maxEntries: tcpCapacity, flags: bpfFlagNoPrealloc},
		"cgroup_udp_redirect":   {name: "sb_cg_udp", mapType: udpMapType, maxEntries: udpCapacity, flags: udpMapFlags},
		"cgroup_udp_token":      {name: "sb_cg_token", mapType: udpMapType, maxEntries: udpCapacity, flags: udpMapFlags},
		"cgroup_udp_peer":       {name: "sb_cg_peer", mapType: CiliumEBPF.LRUHash, maxEntries: udpCapacity},
		"cgroup_udp_flow":       {name: "sb_cg_flow", mapType: CiliumEBPF.LRUHash, maxEntries: flowCapacity},
		"cgroup_uid_policy":     {name: "sb_cg_uid", mapType: CiliumEBPF.LPMTrie, maxEntries: uidCapacity, flags: bpfFlagNoPrealloc},
		"cgroup_bypass_ipv4":    {name: "sb_cg_bypass4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"cgroup_bypass_ipv6":    {name: "sb_cg_bypass6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"cgroup_ipv6_available": {name: "sb_cg_ipv6", mapType: CiliumEBPF.Array, maxEntries: 1},
	})
	if err != nil {
		return err
	}
	runtimeState.control_map_fd = runtimeState.maps["cgroup_control"].FD()
	runtimeState.stats_map_fd = runtimeState.maps["cgroup_stats"].FD()
	runtimeState.tcp_redirect_map_fd = runtimeState.maps["cgroup_tcp_redirect"].FD()
	runtimeState.udp_redirect_map_fd = runtimeState.maps["cgroup_udp_redirect"].FD()
	runtimeState.udp_token_map_fd = runtimeState.maps["cgroup_udp_token"].FD()
	runtimeState.udp_peer_map_fd = runtimeState.maps["cgroup_udp_peer"].FD()
	runtimeState.udp_flow_map_fd = runtimeState.maps["cgroup_udp_flow"].FD()
	runtimeState.uid_policy_map_fd = runtimeState.maps["cgroup_uid_policy"].FD()
	runtimeState.bypass_ipv4_cidr_map_fd = runtimeState.maps["cgroup_bypass_ipv4"].FD()
	runtimeState.bypass_ipv6_cidr_map_fd = runtimeState.maps["cgroup_bypass_ipv6"].FD()
	runtimeState.ipv6_available_map_fd = runtimeState.maps["cgroup_ipv6_available"].FD()
	return nil
}

func probeSocketReleaseSupport() (bool, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:       "sb_rel_probe",
		Type:       CiliumEBPF.CGroupSock,
		AttachType: CiliumEBPF.AttachCgroupInetSockRelease,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
	})
	if err == nil {
		return true, program.Close()
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return false, nil
	}
	return false, err
}

func detachOwnedCgroupPrograms(cgroupFD int) error {
	for _, definition := range cgroupProgramDefinitions {
		first, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			if definition.attachType == CiliumEBPF.AttachCgroupInetSockRelease &&
				(errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)) {
				continue
			}
			return err
		}
		second, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			return err
		}
		if !sameProgramIDs(first, second) {
			return unix.ESTALE
		}
		for _, programID := range first {
			program, openErr := CiliumEBPF.NewProgramFromID(programID)
			if openErr != nil {
				return openErr
			}
			info, infoErr := program.Info()
			if infoErr != nil {
				_ = program.Close()
				return infoErr
			}
			if strings.HasPrefix(info.Name, "sb_ebpf_") {
				if detachErr := rawDetachProgram(cgroupFD, program, definition.attachType); detachErr != nil {
					_ = program.Close()
					return detachErr
				}
			}
			if closeErr := program.Close(); closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}

func queryCgroupProgramIDs(cgroupFD int, attachType CiliumEBPF.AttachType) ([]CiliumEBPF.ProgramID, error) {
	result, err := link.QueryPrograms(link.QueryOptions{Target: cgroupFD, Attach: attachType})
	if err != nil {
		return nil, err
	}
	ids := make([]CiliumEBPF.ProgramID, len(result.Programs))
	for index := range result.Programs {
		ids[index] = result.Programs[index].ID
	}
	return ids, nil
}

func (b *CgroupBackend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

func (b *CgroupBackend) AttachedPrograms() []string {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	programs := make([]string, 0, cgroupProgramCount)
	descriptions := [...]string{
		"sb_ebpf_conn4 (cgroup/connect4)",
		"sb_ebpf_udp4 (cgroup/sendmsg4)",
		"sb_ebpf_urcv4 (cgroup/recvmsg4)",
		"sb_ebpf_conn6 (cgroup/connect6)",
		"sb_ebpf_udp6 (cgroup/sendmsg6)",
		"sb_ebpf_urcv6 (cgroup/recvmsg6)",
		"sb_ebpf_rel (cgroup/sock_release)",
	}
	for slot, program := range b.runtime.programs {
		if program != nil {
			programs = append(programs, descriptions[slot])
		}
	}
	return programs
}

func (b *CgroupBackend) UsesSocketRelease() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime != nil && b.runtime.programs[cgroupProgramSocketRelease] != nil
}

func (b *CgroupBackend) LoadPrograms(listenerPort uint16) error {
	selfTGID, err := b.probeSelfTGID()
	if err != nil {
		return err
	}
	return b.loadPrograms(listenerPort, selfTGID)
}

func (b *CgroupBackend) probeSelfTGID() (uint32, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return 0, err
	}
	probeMap, err := newRuntimeMap("sb_tgid_probe", CiliumEBPF.Array, 4, 4, 1, 0)
	if err != nil {
		return 0, nil
	}
	defer probeMap.Close()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:       "sb_tgid_probe",
		Type:       CiliumEBPF.CGroupSockAddr,
		AttachType: CiliumEBPF.AttachCGroupInet4Connect,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, probeMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.Mov.Reg(asm.R6, asm.R0),
			asm.FnGetCurrentPidTgid.Call(),
			asm.RSh.Imm(asm.R0, 32),
			asm.StoreMem(asm.R6, 0, asm.R0, asm.Word),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("exit"),
			asm.Return(),
		},
	})
	if err != nil {
		return 0, nil
	}
	defer program.Close()
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	if err = attachProgramRaw(cgroupFD, program, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
		return 0, nil
	}
	socketFD, socketErr := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if socketErr == nil {
		_ = unix.Connect(socketFD, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}})
		_ = unix.Close(socketFD)
	}
	var selfTGID uint32
	_ = probeMap.Lookup(uint32(0), &selfTGID)
	if err = rawDetachProgram(cgroupFD, program, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
		return 0, eBPFOperationError("detach BPF-visible self TGID probe", err)
	}
	return selfTGID, nil
}

func (b *CgroupBackend) loadPrograms(listenerPort uint16, selfTGID uint32) error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	for _, program := range b.runtime.programs {
		if program != nil {
			return eBPFOperationError("load eBPF inbound programs", unix.EALREADY)
		}
	}
	if listenerPort == 0 {
		return E.New("missing eBPF redirect listener port")
	}
	tryTGID := selfTGID != 0
	if err := b.updateCgroupControl(listenerPort, func() uint32 {
		if tryTGID {
			return selfTGID
		}
		return 0
	}()); err != nil {
		return E.Cause(err, "update cgroup control map")
	}
	if tryTGID {
		programs, err := b.loadCgroupObjectPrograms(true)
		if err == nil {
			b.runtime.programs = programs
			b.runtime.self_bypass_tgid = true
			b.selfBypassTGID.Store(true)
			b.pendingSocketCookies = nil
			return nil
		}
	}
	socketBypass, err := newRuntimeMap("sb_cg_sock_byp", CiliumEBPF.LRUHash, 8, 1, b.runtime.socket_bypass_capacity, 0)
	if err != nil {
		return err
	}
	b.runtime.maps["cgroup_socket_bypass"] = socketBypass
	b.runtime.bypass_socket_cookie_map_fd = socketBypass.FD()
	b.socketBypassMapFD = socketBypass.FD()
	if err = b.updateCgroupControl(listenerPort, 0); err != nil {
		return E.Cause(err, "update cgroup control map fallback")
	}
	programs, err := b.loadCgroupObjectPrograms(false)
	if err != nil {
		return eBPFBackendOperationError("load eBPF inbound programs", verifierErrorStage(err), err)
	}
	b.runtime.programs = programs
	b.runtime.self_bypass_tgid = false
	value := uint8(1)
	for cookie := range b.pendingSocketCookies {
		cookie := cookie
		if err = updateMap(b.socketBypassMapFD, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
			return E.Cause(err, "register pending eBPF bypass socket")
		}
	}
	b.pendingSocketCookies = nil
	return nil
}

func (b *CgroupBackend) loadCgroupObjectPrograms(tgidMode bool) ([]*CiliumEBPF.Program, error) {
	selections := make([]programSelection, 0, cgroupProgramCount)
	slots := make([]int, 0, cgroupProgramCount)
	for slot, definition := range cgroupProgramDefinitions {
		if !b.cgroupProgramEnabled(slot) {
			continue
		}
		selections = append(selections, programSelection{
			section: b.cgroupProgramSection(slot, tgidMode),
			name:    definition.name,
		})
		slots = append(slots, slot)
	}
	loaded, err := loadObjectPrograms(loadCgroup, b.runtime.maps, selections)
	if err != nil {
		return nil, err
	}
	programs := make([]*CiliumEBPF.Program, cgroupProgramCount)
	for index, slot := range slots {
		programs[slot] = loaded[index]
	}
	return programs, nil
}

func (b *CgroupBackend) cgroupProgramEnabled(slot int) bool {
	enableIPv4 := b.redirectIPv4.IsValid()
	enableIPv6 := b.enableIPv6
	switch slot {
	case cgroupProgramConnect4:
		return enableIPv4
	case cgroupProgramUDP4Sendmsg, cgroupProgramUDP4Recvmsg:
		return enableIPv4 && b.runtime.enable_udp
	case cgroupProgramConnect6:
		return enableIPv4 || enableIPv6
	case cgroupProgramUDP6Sendmsg, cgroupProgramUDP6Recvmsg:
		return (enableIPv4 || enableIPv6) && b.runtime.enable_udp
	case cgroupProgramSocketRelease:
		return b.runtime.enable_udp && b.runtime.socket_release_supported
	default:
		return false
	}
}

func (b *CgroupBackend) cgroupProgramSection(slot int, tgidMode bool) string {
	mode := "cookie"
	if tgidMode {
		mode = "tgid"
	}
	protocolSuffix := ""
	if b.runtime.enable_tcp && !b.runtime.enable_udp {
		protocolSuffix = "_tcp"
	} else if !b.runtime.enable_tcp && b.runtime.enable_udp {
		protocolSuffix = "_udp"
	}
	switch slot {
	case cgroupProgramConnect4:
		return "cgroup/connect4_" + mode + protocolSuffix
	case cgroupProgramUDP4Sendmsg:
		return "cgroup/sendmsg4_" + mode
	case cgroupProgramUDP4Recvmsg:
		return "cgroup/recvmsg4"
	case cgroupProgramConnect6:
		if !b.enableIPv6 {
			return "cgroup/connect6_mapped_" + mode + protocolSuffix
		}
		return "cgroup/connect6_" + mode + protocolSuffix
	case cgroupProgramUDP6Sendmsg:
		if !b.enableIPv6 {
			return "cgroup/sendmsg6_mapped_" + mode
		}
		return "cgroup/sendmsg6_" + mode
	case cgroupProgramUDP6Recvmsg:
		if !b.enableIPv6 {
			return "cgroup/recvmsg6_mapped"
		}
		return "cgroup/recvmsg6"
	case cgroupProgramSocketRelease:
		return "cgroup/release_" + mode
	default:
		return ""
	}
}

func (b *CgroupBackend) updateCgroupControl(listenerPort uint16, selfTGID uint32) error {
	var flags uint32
	if b.runtime.enable_tcp {
		flags |= cgroupFlagTCP
	}
	if b.runtime.enable_udp {
		flags |= cgroupFlagUDP
	}
	if b.redirectIPv4.IsValid() {
		flags |= cgroupFlagIPv4
	}
	if b.enableIPv6 {
		flags |= cgroupFlagIPv6
	}
	if b.hijackDNS {
		flags |= cgroupFlagHijackDNS
	}
	if b.bypassPrivateAddress {
		flags |= cgroupFlagBypassPrivateAddress
	}
	if b.dnsRespectBypass {
		flags |= cgroupFlagDNSRespectBypass
	}
	if b.runtime.uid_policy {
		flags |= cgroupFlagUIDPolicy
	}
	if b.runtime.uid_default_bypass {
		flags |= cgroupFlagUIDDefaultBypass
	}
	if b.runtime.bypass_ipv4_policy {
		flags |= cgroupFlagBypassIPv4
	}
	if b.runtime.bypass_ipv6_policy {
		flags |= cgroupFlagBypassIPv6
	}
	if b.runtime.auto_ipv6 {
		flags |= cgroupFlagAutoIPv6
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported {
		flags |= cgroupFlagUDPFlow
	}
	ipv4Prefix, ipv4HostMask := cgroupIPv4Redirect(b.redirectIPv4)
	control := cgroupControl{
		Flags:                flags,
		SelfTGID:             selfTGID,
		UDPTimeoutSeconds:    b.udpTimeoutSeconds,
		RedirectIPv4Prefix:   ipv4Prefix,
		RedirectIPv4HostMask: ipv4HostMask,
		ListenerPort:         listenerPort,
	}
	if b.redirectIPv6.IsValid() {
		address := b.redirectIPv6.Addr().As16()
		copy(control.RedirectIPv6Prefix[:], address[:8])
	}
	key := uint32(0)
	return updateMap(b.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control))
}

func (b *CgroupBackend) UpdateIPv6Available(available bool) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.updateIPv6AvailableLocked(available)
}

func (b *CgroupBackend) updateIPv6AvailableLocked(available bool) (bool, error) {
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	if !b.autoIPv6 || b.ipv6AvailableMapFD < 0 {
		return false, nil
	}
	if b.ipv6Available == available {
		return false, nil
	}
	key := uint32(0)
	value := uint32(0)
	if available {
		value = 1
	}
	if err := updateMap(b.ipv6AvailableMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return false, E.Cause(err, "update IPv6 availability eBPF map")
	}
	b.ipv6Available = available
	return true, nil
}

func (b *CgroupBackend) SelfBypassMode() string {
	if b == nil {
		return ""
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return ""
	}
	if b.runtime.self_bypass_tgid {
		return "tgid"
	}
	return "socket_cookie"
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	for slot, program := range b.runtime.programs {
		if program == nil {
			continue
		}
		if err := attachProgramRaw(cgroupFD, program, cgroupProgramDefinitions[slot].attachType); err != nil {
			_ = b.detachProgramsLocked()
			return eBPFBackendOperationError("attach eBPF inbound", cgroupProgramDefinitions[slot].name, err)
		}
		b.runtime.attached[slot] = true
	}
	return nil
}

func (b *CgroupBackend) detachProgramsLocked() error {
	if b.runtime == nil || b.runtime.cgroupFile == nil {
		return nil
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	var detachErr error
	for slot := cgroupProgramCount - 1; slot >= 0; slot-- {
		if !b.runtime.attached[slot] {
			continue
		}
		err := rawDetachProgram(cgroupFD, b.runtime.programs[slot], cgroupProgramDefinitions[slot].attachType)
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			b.runtime.attached[slot] = false
			continue
		}
		detachErr = E.Errors(detachErr, err)
	}
	return detachErr
}

func (b *CgroupBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	if err := b.detachProgramsLocked(); err != nil {
		return E.Cause(err, "detach eBPF inbound")
	}
	closeErr := closePrograms(b.runtime.programs)
	closeErr = E.Errors(closeErr, closeMaps(b.runtime.maps))
	if b.runtime.cgroupFile != nil {
		closeErr = E.Errors(closeErr, b.runtime.cgroupFile.Close())
	}
	b.runtime = nil
	b.tcpRedirectMapFD = -1
	b.udpRedirectMapFD = -1
	b.udpFlowMapFD = -1
	b.socketBypassMapFD = -1
	b.pendingSocketCookies = nil
	b.bypassIPv4CIDRMapFD = -1
	b.bypassIPv6CIDRMapFD = -1
	b.ipv6AvailableMapFD = -1
	b.bypassIPv4CIDR = nil
	b.bypassIPv6CIDR = nil
	return closeErr
}

func (b *CgroupBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
