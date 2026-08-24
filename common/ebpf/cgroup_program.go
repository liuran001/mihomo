//go:build with_ebpf && (linux || android)

package ebpf

import (
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

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
	if err = b.validateCgroupProgramSet(programs); err != nil {
		_ = closePrograms(programs)
		return nil, err
	}
	return programs, nil
}

func (b *CgroupBackend) validateCgroupProgramSet(programs []*CiliumEBPF.Program) error {
	if !b.runtime.enable_udp {
		return nil
	}
	if len(programs) <= cgroupProgramSocketRelease {
		return E.New("incomplete cgroup program set")
	}
	hasSocketRelease := programs[cgroupProgramSocketRelease] != nil
	if hasSocketRelease != b.runtime.socket_release_supported {
		return E.New(
			"inconsistent UDP cleanup program set: socket_release_program=", hasSocketRelease,
			", socket_release_probe=", b.runtime.socket_release_supported,
		)
	}
	return nil
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
		return "cgroup/sock_release_" + mode
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
	if b.bypassPrivateAddress {
		flags |= cgroupFlagBypassPrivateAddress
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
	flags |= b.hostAddressFlags()
	if b.runtime.auto_ipv6 {
		flags |= cgroupFlagAutoIPv6
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported {
		flags |= cgroupFlagUDPFlow
	}
	if b.fakeIPIPv4.IsValid() {
		flags |= cgroupFlagFakeIPIPv4
	}
	if b.fakeIPIPv6.IsValid() {
		flags |= cgroupFlagFakeIPIPv6
	}
	ipv4Prefix, ipv4HostMask := cgroupIPv4Redirect(b.redirectIPv4)
	control := cgroupControl{
		Flags:                flags,
		SelfTGID:             selfTGID,
		UDPTimeoutSeconds:    b.udpTimeoutSeconds,
		DNSMode:              b.dnsMode,
		RedirectIPv4Prefix:   ipv4Prefix,
		RedirectIPv4HostMask: ipv4HostMask,
		ListenerPort:         listenerPort,
	}
	if b.redirectIPv6.IsValid() {
		address := b.redirectIPv6.Addr().As16()
		copy(control.RedirectIPv6Prefix[:], address[:8])
	}
	if b.fakeIPIPv4.IsValid() {
		control.FakeIPIPv4Prefix = b.fakeIPIPv4.Addr().As4()
		control.FakeIPIPv4Mask = prefixMask4(b.fakeIPIPv4.Bits())
	}
	if b.fakeIPIPv6.IsValid() {
		control.FakeIPIPv6Prefix = b.fakeIPIPv6.Addr().As16()
		control.FakeIPIPv6Mask = prefixMask16(b.fakeIPIPv6.Bits())
	}
	key := uint32(0)
	return updateMap(b.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control))
}

func (b *CgroupBackend) hostAddressFlags() uint32 {
	var flags uint32
	if len(b.hostIPv4) > 0 {
		flags |= cgroupFlagHostIPv4
	}
	if b.enableIPv6 && len(b.hostIPv6) > 0 {
		flags |= cgroupFlagHostIPv6
	}
	return flags
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
