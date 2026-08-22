//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"sync"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type sharedNetworkTCXLink struct {
	link      interface{ Close() error }
	linkID    link.ID
	programID CiliumEBPF.ProgramID
	attach    CiliumEBPF.AttachType
}

type SharedNetworkTCXAttachment struct {
	access         sync.Mutex
	interfaceIndex int
	ingress        sharedNetworkTCXLink
	egress         sharedNetworkTCXLink
	pendingCleanup []sharedNetworkTCXLink
}

type RuntimeTCXLinkStatus struct {
	ProgramID uint32 `json:"program_id"`
	LinkID    uint32 `json:"link_id"`
	Attached  bool   `json:"attached"`
	Error     string `json:"error,omitempty"`
}

type SharedNetworkTCXRuntimeStatus struct {
	Healthy bool                 `json:"healthy"`
	Ingress RuntimeTCXLinkStatus `json:"ingress"`
	Egress  RuntimeTCXLinkStatus `json:"egress"`
}

func (b *SharedNetworkBackend) TryAttachTCX(interfaceIndex int) (*SharedNetworkTCXAttachment, bool, error) {
	if b == nil {
		return nil, false, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if err := b.requireUsableLocked(); err != nil {
		return nil, false, err
	}
	attachment, err := attachSharedNetworkTCX(
		interfaceIndex,
		b.runtime.programs[sharedNetworkProgramIngress],
		b.runtime.programs[sharedNetworkProgramEgress],
	)
	if err != nil {
		if isTCXUnavailable(err) {
			return nil, false, nil
		}
		return nil, false, E.Cause(err, "attach shared-network TCX")
	}
	return attachment, true, nil
}

func attachSharedNetworkTCX(
	interfaceIndex int,
	ingressProgram *CiliumEBPF.Program,
	egressProgram *CiliumEBPF.Program,
) (*SharedNetworkTCXAttachment, error) {
	ingress, err := attachSharedNetworkTCXLink(interfaceIndex, ingressProgram, CiliumEBPF.AttachTCXIngress)
	if err != nil {
		return nil, err
	}
	egress, err := attachSharedNetworkTCXLink(interfaceIndex, egressProgram, CiliumEBPF.AttachTCXEgress)
	if err != nil {
		return nil, E.Errors(err, ingress.link.Close())
	}
	return &SharedNetworkTCXAttachment{
		interfaceIndex: interfaceIndex,
		ingress:        ingress,
		egress:         egress,
	}, nil
}

func attachSharedNetworkTCXLink(
	interfaceIndex int,
	program *CiliumEBPF.Program,
	attachType CiliumEBPF.AttachType,
) (sharedNetworkTCXLink, error) {
	linkInstance, err := link.AttachTCX(link.TCXOptions{
		Interface: interfaceIndex,
		Program:   program,
		Attach:    attachType,
	})
	if err != nil {
		return sharedNetworkTCXLink{}, err
	}
	info, err := linkInstance.Info()
	if err != nil {
		return sharedNetworkTCXLink{}, E.Errors(err, linkInstance.Close())
	}
	return sharedNetworkTCXLink{
		link:      linkInstance,
		linkID:    info.ID,
		programID: info.Program,
		attach:    attachType,
	}, nil
}

func (b *SharedNetworkBackend) RepairTCX(
	attachment *SharedNetworkTCXAttachment,
	interfaceIndex int,
) (bool, error) {
	if b == nil || attachment == nil {
		return false, errBackendClosed
	}
	attachment.access.Lock()
	defer attachment.access.Unlock()
	if err := attachment.closePendingLocked(); err != nil {
		return false, E.Cause(err, "retry pending shared-network TCX cleanup")
	}
	healthy, err := attachment.healthyLocked(interfaceIndex)
	if err != nil && !isTCXAttachmentStale(err) {
		return false, err
	}
	if healthy {
		return false, nil
	}

	b.access.RLock()
	defer b.access.RUnlock()
	if err = b.requireUsableLocked(); err != nil {
		return false, err
	}
	replacement, err := attachSharedNetworkTCX(
		interfaceIndex,
		b.runtime.programs[sharedNetworkProgramIngress],
		b.runtime.programs[sharedNetworkProgramEgress],
	)
	if err != nil {
		return false, E.Cause(err, "repair shared-network TCX")
	}
	return attachment.commitReplacementLocked(replacement)
}

func (a *SharedNetworkTCXAttachment) commitReplacementLocked(replacement *SharedNetworkTCXAttachment) (bool, error) {
	if cleanupErr := a.closePendingLocked(); cleanupErr != nil {
		replacementCloseErr := replacement.closeLocked()
		a.retainRemainingLinks(replacement)
		if replacementCloseErr == nil {
			return false, E.Cause(cleanupErr, "retry pending shared-network TCX cleanup")
		}
		return false, E.Errors(
			E.Cause(cleanupErr, "retry pending shared-network TCX cleanup"),
			E.Cause(replacementCloseErr, "rollback repaired shared-network TCX"),
		)
	}
	closeErr := a.closeLocked()
	if closeErr != nil {
		// Do not commit a replacement while part of the old attachment is
		// still owned by this object. Keeping the old link references lets the
		// next reconcile retry cleanup instead of leaking an untracked TCX link
		// or repeatedly stacking replacements.
		replacementCloseErr := replacement.closeLocked()
		a.retainRemainingLinks(replacement)
		if replacementCloseErr == nil {
			return false, closeErr
		}
		return false, E.Errors(closeErr, E.Cause(replacementCloseErr, "rollback repaired shared-network TCX"))
	}
	a.interfaceIndex = replacement.interfaceIndex
	a.ingress = replacement.ingress
	a.egress = replacement.egress
	return true, nil
}

func (a *SharedNetworkTCXAttachment) retainRemainingLinks(attachment *SharedNetworkTCXAttachment) {
	if attachment.ingress.link != nil {
		a.pendingCleanup = append(a.pendingCleanup, attachment.ingress)
		attachment.ingress = sharedNetworkTCXLink{}
	}
	if attachment.egress.link != nil {
		a.pendingCleanup = append(a.pendingCleanup, attachment.egress)
		attachment.egress = sharedNetworkTCXLink{}
	}
	if len(attachment.pendingCleanup) != 0 {
		a.pendingCleanup = append(a.pendingCleanup, attachment.pendingCleanup...)
		attachment.pendingCleanup = nil
	}
}

func (a *SharedNetworkTCXAttachment) healthyLocked(interfaceIndex int) (bool, error) {
	if a.interfaceIndex != interfaceIndex || a.ingress.link == nil || a.egress.link == nil {
		return false, nil
	}
	for _, state := range []sharedNetworkTCXLink{a.ingress, a.egress} {
		result, err := link.QueryPrograms(link.QueryOptions{
			Target: interfaceIndex,
			Attach: state.attach,
		})
		if err != nil {
			return false, err
		}
		found := false
		for _, program := range result.Programs {
			if program.ID != state.programID {
				continue
			}
			linkID, haveLinkID := program.LinkID()
			if !haveLinkID || linkID == state.linkID {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

func (a *SharedNetworkTCXAttachment) RuntimeStatus(interfaceIndex int) SharedNetworkTCXRuntimeStatus {
	if a == nil {
		return SharedNetworkTCXRuntimeStatus{}
	}
	a.access.Lock()
	defer a.access.Unlock()
	status := SharedNetworkTCXRuntimeStatus{
		Ingress: runtimeTCXLinkStatus(a.ingress, interfaceIndex),
		Egress:  runtimeTCXLinkStatus(a.egress, interfaceIndex),
	}
	status.Healthy = a.interfaceIndex == interfaceIndex && status.Ingress.Attached && status.Egress.Attached
	return status
}

func runtimeTCXLinkStatus(state sharedNetworkTCXLink, interfaceIndex int) RuntimeTCXLinkStatus {
	status := RuntimeTCXLinkStatus{
		ProgramID: uint32(state.programID),
		LinkID:    uint32(state.linkID),
	}
	if state.link == nil {
		return status
	}
	result, err := link.QueryPrograms(link.QueryOptions{Target: interfaceIndex, Attach: state.attach})
	if err != nil {
		status.Error = err.Error()
		return status
	}
	for _, program := range result.Programs {
		if program.ID != state.programID {
			continue
		}
		linkID, haveLinkID := program.LinkID()
		if !haveLinkID || linkID == state.linkID {
			status.Attached = true
			break
		}
	}
	return status
}

func (a *SharedNetworkTCXAttachment) Close() error {
	if a == nil {
		return nil
	}
	a.access.Lock()
	defer a.access.Unlock()
	return a.closeLocked()
}

func (a *SharedNetworkTCXAttachment) closeLocked() error {
	var closeErr error
	if a.ingress.link != nil {
		err := a.ingress.link.Close()
		closeErr = E.Errors(closeErr, err)
		if err == nil {
			a.ingress = sharedNetworkTCXLink{}
		}
	}
	if a.egress.link != nil {
		err := a.egress.link.Close()
		closeErr = E.Errors(closeErr, err)
		if err == nil {
			a.egress = sharedNetworkTCXLink{}
		}
	}
	return E.Errors(closeErr, a.closePendingLocked())
}

func (a *SharedNetworkTCXAttachment) closePendingLocked() error {
	var closeErr error
	remaining := a.pendingCleanup[:0]
	for _, state := range a.pendingCleanup {
		if state.link == nil {
			continue
		}
		if err := state.link.Close(); err != nil {
			closeErr = E.Errors(closeErr, err)
			remaining = append(remaining, state)
		}
	}
	a.pendingCleanup = remaining
	return closeErr
}

func isTCXUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, linuxErrnoNotSupported) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES)
}

func isTCXAttachmentStale(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.ENOLINK) ||
		errors.Is(err, unix.ESTALE)
}
