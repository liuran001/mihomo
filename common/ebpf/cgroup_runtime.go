//go:build with_ebpf && (linux || android)

package ebpf

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

func (b *CgroupBackend) RuntimeStatus() CgroupRuntimeStatus {
	if b == nil {
		return CgroupRuntimeStatus{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return CgroupRuntimeStatus{}
	}
	status := CgroupRuntimeStatus{
		UDPCleanupMode:            cgroupUDPCleanupModeLocked(b.runtime),
		UDPRecoveryUpdateFailures: b.udpRecoveryUpdateFailures.Load(),
		Maps:                      b.statusCollector.collect(b.runtime.maps),
	}
	var statsErr error
	status.TCPRedirectReservationFailures, statsErr = b.redirectReservationFailuresLocked(ProtocolTCP)
	if statsErr == nil {
		status.UDPRedirectReservationFailures, statsErr = b.redirectReservationFailuresLocked(ProtocolUDP)
	}
	if statsErr != nil {
		status.StatsError = statsErr.Error()
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	for slot, definition := range cgroupProgramDefinitions {
		program := b.runtime.programs[slot]
		if program == nil {
			continue
		}
		programStatus := runtimeProgramStatus(program, definition.name, b.cgroupProgramSection(slot, b.runtime.self_bypass_tgid))
		programStatus.AttachType = definition.attachType.String()
		if programLink := b.runtime.links[slot]; programLink != nil {
			programStatus.AttachmentMode = "bpf_link"
			linkInfo, linkErr := programLink.Info()
			if linkErr != nil {
				programStatus.Error = "query BPF link: " + linkErr.Error()
			} else {
				programStatus.LinkID = uint32(linkInfo.ID)
				programStatus.Attached = uint32(linkInfo.Program) == programStatus.ID
			}
		} else if b.runtime.attached[slot] {
			programStatus.AttachmentMode = "prog_attach"
		}
		programIDs, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			if programStatus.Error == "" {
				programStatus.Error = err.Error()
			} else {
				programStatus.Error += "; query cgroup programs: " + err.Error()
			}
		} else {
			for _, programID := range programIDs {
				if uint32(programID) == programStatus.ID {
					programStatus.Attached = true
					break
				}
			}
		}
		status.Programs = append(status.Programs, programStatus)
	}
	return status
}

func (b *CgroupBackend) UsesSocketRelease() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime != nil && b.runtime.socket_release_supported &&
		b.runtime.programs[cgroupProgramSocketRelease] != nil
}

func (b *CgroupBackend) UDPCleanupMode() string {
	if b == nil {
		return cgroupUDPCleanupDisabled
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return cgroupUDPCleanupModeLocked(b.runtime)
}

func cgroupUDPCleanupModeLocked(runtimeState *cgroupRuntime) string {
	if runtimeState == nil || !runtimeState.enable_udp {
		return cgroupUDPCleanupDisabled
	}
	if !runtimeState.socket_release_supported {
		return cgroupUDPCleanupLRUFallback
	}
	if len(runtimeState.programs) <= cgroupProgramSocketRelease ||
		runtimeState.programs[cgroupProgramSocketRelease] == nil {
		return cgroupUDPCleanupInvalid
	}
	return cgroupUDPCleanupSocketRelease
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
