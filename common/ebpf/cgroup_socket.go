//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	mapLookupAndDeleteUnknown int32 = iota
	mapLookupAndDeleteSupported
	mapLookupAndDeleteUnsupported
)

func (b *CgroupBackend) SocketProtectFunc() control.Func {
	if b == nil {
		return nil
	}
	return func(network string, address string, rawConn syscall.RawConn) error {
		if b.selfBypassTGID.Load() {
			return nil
		}
		return control.Raw(rawConn, func(fd uintptr) error {
			cookie, err := readSocketCookie(fd)
			if err != nil {
				return E.Cause(err, "read socket cookie")
			}
			b.access.RLock()
			if b.runtime == nil {
				b.access.RUnlock()
				return errBackendClosed
			}
			if b.runtime.self_bypass_tgid {
				b.access.RUnlock()
				return nil
			}
			if b.socketBypassMapFD >= 0 {
				err = registerSocketCookie(b.socketBypassMapFD, cookie)
				b.access.RUnlock()
				return err
			}
			b.access.RUnlock()

			b.access.Lock()
			defer b.access.Unlock()
			if b.runtime == nil {
				return errBackendClosed
			}
			if b.runtime.self_bypass_tgid {
				return nil
			}
			if b.socketBypassMapFD >= 0 {
				return registerSocketCookie(b.socketBypassMapFD, cookie)
			}
			if b.pendingSocketCookies == nil {
				b.pendingSocketCookies = make(map[uint64]struct{})
			}
			b.pendingSocketCookies[cookie] = struct{}{}
			return nil
		})
	}
}

func registerSocketCookie(mapFD int, cookie uint64) error {
	value := uint8(1)
	if err := updateMap(mapFD, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "register eBPF bypass socket")
	}
	return nil
}

func (b *CgroupBackend) LookupOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, false)
}

func (b *CgroupBackend) TakeOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, true)
}

func (b *CgroupBackend) lookupOriginal(
	protocol uint8,
	listenerDestination netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestinationValue
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return OriginalDestination{}, err
	}
	if deleteAfterLookup {
		err = b.takeMapElement(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	} else {
		err = lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) RecoverUDPOriginal(listenerDestination netip.AddrPort) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(ProtocolUDP, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	var original originalDestinationValue
	consumed, err := b.takeUDPRecoveryElement(&key, &original)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup recoverable UDP original destination")
	}
	recoveryOriginal := original
	if err = updateMapWithFlags(
		b.udpRedirectMapFD,
		unsafe.Pointer(&key),
		unsafe.Pointer(&original),
		bpfNoExist,
	); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return OriginalDestination{}, b.rollbackConsumedUDPRecovery(
				&key,
				&recoveryOriginal,
				consumed,
				E.Cause(err, "restore UDP original destination"),
			)
		}
		var existing originalDestinationValue
		if err = lookupMap(b.udpRedirectMapFD, unsafe.Pointer(&key), unsafe.Pointer(&existing)); err != nil {
			return OriginalDestination{}, b.rollbackConsumedUDPRecovery(
				&key,
				&recoveryOriginal,
				consumed,
				E.Cause(err, "lookup concurrently restored UDP original destination"),
			)
		}
		original = existing
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) takeUDPRecoveryElement(
	key *listenerLookupKey,
	original *originalDestinationValue,
) (bool, error) {
	if b.udpRecoveryConsumeMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(
			b.udpRecoveryMapFD,
			unsafe.Pointer(key),
			unsafe.Pointer(original),
		)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.udpRecoveryConsumeMode.Store(mapLookupAndDeleteSupported)
			return err == nil, err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return false, err
		}
		b.udpRecoveryConsumeMode.Store(mapLookupAndDeleteUnsupported)
	}
	// A lookup+delete fallback could remove a newer kernel update between the
	// two syscalls. Preserve the LRU entry on kernels without atomic support.
	err := lookupMap(
		b.udpRecoveryMapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(original),
	)
	return false, err
}

func (b *CgroupBackend) rollbackConsumedUDPRecovery(
	key *listenerLookupKey,
	original *originalDestinationValue,
	consumed bool,
	recoveryErr error,
) error {
	if !consumed {
		return recoveryErr
	}
	err := updateMapWithFlags(
		b.udpRecoveryMapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(original),
		bpfNoExist,
	)
	if err == nil || errors.Is(err, unix.EEXIST) {
		return recoveryErr
	}
	return E.Errors(recoveryErr, E.Cause(err, "restore consumed UDP recovery state"))
}

func (b *CgroupBackend) RecoverConnectedUDPOriginal(listenerDestination netip.AddrPort) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	listener, err := makeListenerLookupKey(ProtocolUDP, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	tokenMap := b.runtime.maps["cgroup_udp_token"]
	if tokenMap == nil {
		return OriginalDestination{}, E.New("connected UDP token map is unavailable")
	}
	cookie, err := b.findConnectedUDPToken(tokenMap, listener)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "scan connected UDP token state")
	}
	if cookie == 0 {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "find connected UDP token state")
	}
	var verifiedToken listenerLookupKey
	if err = lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&cookie),
		unsafe.Pointer(&verifiedToken),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "verify connected UDP token state")
	}
	if verifiedToken != listener {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP token changed during recovery")
	}
	peerKey := udpPeerKey{SocketCookie: cookie}
	var peer udpPeerValue
	if err = lookupMap(
		b.runtime.udp_peer_map_fd,
		unsafe.Pointer(&peerKey),
		unsafe.Pointer(&peer),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup connected UDP peer state")
	}
	original, err := originalDestinationFromUDPPeer(cookie, peer)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "validate connected UDP peer state")
	}
	if original.Family != listener.Family {
		return OriginalDestination{}, E.New(
			"connected UDP token and peer family mismatch: token=", listener.Family,
			", peer=", original.Family,
		)
	}
	if err = lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&cookie),
		unsafe.Pointer(&verifiedToken),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "revalidate connected UDP token state")
	}
	if verifiedToken != listener {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP token changed during recovery")
	}
	err = updateMapWithFlags(
		b.udpRedirectMapFD,
		unsafe.Pointer(&listener),
		unsafe.Pointer(&original),
		bpfNoExist,
	)
	if errors.Is(err, unix.EEXIST) {
		var existing originalDestinationValue
		if lookupErr := lookupMap(
			b.udpRedirectMapFD,
			unsafe.Pointer(&listener),
			unsafe.Pointer(&existing),
		); lookupErr != nil {
			return OriginalDestination{}, E.Cause(lookupErr, "verify concurrently restored connected UDP redirect")
		}
		if existing != original {
			return OriginalDestination{}, E.New("connected UDP redirect token was concurrently claimed")
		}
		err = nil
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "restore connected UDP redirect state")
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) findConnectedUDPToken(
	tokenMap *CiliumEBPF.Map,
	listener listenerLookupKey,
) (uint64, error) {
	// This searches the token map BY VALUE, so it is inherently O(entries).
	// It runs inline on the UDP read loop, so it must stay bounded: a densely
	// populated map would otherwise stall packet reception for the whole scan.
	// Giving up early is safe — the caller treats ENOENT as "cannot recover"
	// and drops the packet, which is what an exhaustive miss would do anyway.
	budget := min(b.mapCapacity.UDPRedirect, connectedUDPTokenScanBudget)
	// Connected UDP recovery is a cold path. Batch lookup avoids one syscall
	// per token on kernels that implement BPF_MAP_LOOKUP_BATCH, while the
	// support state keeps vendor/old kernels on the proven iterator path.
	if b.connectedUDPTokenLookupSupport.mode.Load() != mapBatchUnsupported {
		batchCapacity := min(uint32(mapBatchMaxEntries), budget)
		if cap(b.connectedUDPTokenKeys) < int(batchCapacity) {
			b.connectedUDPTokenKeys = make([]uint64, batchCapacity)
			b.connectedUDPTokenValues = make([]listenerLookupKey, batchCapacity)
		} else {
			b.connectedUDPTokenKeys = b.connectedUDPTokenKeys[:batchCapacity]
			b.connectedUDPTokenValues = b.connectedUDPTokenValues[:batchCapacity]
		}
		var cursor CiliumEBPF.MapBatchCursor
		var scanned uint32
		for scanned < budget {
			batchSize := min(batchCapacity, budget-scanned)
			countValue, batchErr := tokenMap.BatchLookup(
				&cursor,
				b.connectedUDPTokenKeys[:batchSize],
				b.connectedUDPTokenValues[:batchSize],
				nil,
			)
			count := uint32(countValue)
			for index := range count {
				if b.connectedUDPTokenValues[index] == listener {
					b.connectedUDPTokenLookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
					return b.connectedUDPTokenKeys[index], nil
				}
			}
			scanned += count
			if errors.Is(batchErr, CiliumEBPF.ErrKeyNotExist) {
				b.connectedUDPTokenLookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
				return 0, unix.ENOENT
			}
			if batchErr != nil {
				if !mapBatchUnsupportedError(batchErr) {
					return 0, batchErr
				}
				b.connectedUDPTokenLookupSupport.mode.Store(mapBatchUnsupported)
				break
			}
			if count == 0 {
				return 0, unix.EIO
			}
			b.connectedUDPTokenLookupSupport.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
		}
		if b.connectedUDPTokenLookupSupport.mode.Load() == mapBatchSupported {
			return 0, unix.ENOENT
		}
	}
	var (
		cookie       uint64
		currentToken listenerLookupKey
		scanned      uint32
	)
	iterator := tokenMap.Iterate()
	for iterator.Next(&cookie, &currentToken) {
		scanned++
		if currentToken == listener {
			return cookie, nil
		}
		if scanned >= budget {
			break
		}
	}
	if err := iterator.Err(); err != nil {
		return 0, err
	}
	return 0, unix.ENOENT
}

func (b *CgroupBackend) ReserveUDPReplyRedirect(
	destination netip.AddrPort,
	listenerPort uint16,
) (netip.Addr, error) {
	if b == nil {
		return netip.Addr{}, errBackendClosed
	}
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().IsUnspecified() {
		return netip.Addr{}, E.New("invalid UDP reply source: ", destination)
	}
	if listenerPort == 0 {
		return netip.Addr{}, E.New("invalid UDP redirect listener port")
	}
	var original originalDestinationValue
	original.Protocol = ProtocolUDP
	original.Port = destination.Port()
	if err := encodeAddress(&original.Family, &original.Addr, destination.Addr()); err != nil {
		return netip.Addr{}, E.Cause(err, "encode UDP reply source")
	}

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return netip.Addr{}, errBackendClosed
	}
	prefix := b.redirectIPv4
	if destination.Addr().Is6() {
		prefix = b.redirectIPv6
	}
	if !prefix.IsValid() {
		return netip.Addr{}, E.New("UDP reply source address family is not enabled: ", destination)
	}
	for attempt := 0; attempt < userspaceReplyTokenAttempts; {
		sequence := b.udpReplyTokenSequence.Add(1)
		token, valid := userspaceReplyToken(prefix, sequence)
		if !valid {
			continue
		}
		attempt++
		key, err := makeListenerLookupKey(ProtocolUDP, netip.AddrPortFrom(token, listenerPort))
		if err != nil {
			return netip.Addr{}, err
		}
		err = updateMapWithFlags(
			b.udpRedirectMapFD,
			unsafe.Pointer(&key),
			unsafe.Pointer(&original),
			bpfNoExist,
		)
		if err == nil {
			return token, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return netip.Addr{}, E.Cause(err, "reserve UDP reply redirect")
		}
	}
	return netip.Addr{}, E.New("reserve UDP reply redirect: token attempts exhausted")
}

func (b *CgroupBackend) takeMapElement(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	if b.lookupAndDeleteMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(mapFD, key, value)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.lookupAndDeleteMode.Store(mapLookupAndDeleteSupported)
			return err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return err
		}
		b.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
	}
	if err := lookupMap(mapFD, key, value); err != nil {
		return err
	}
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func mapLookupAndDeleteUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, linuxErrnoNotSupported)
}

// deleteStaleRedirect removes an entry only when the value returned by the
// kernel's atomic lookup-and-delete still matches the scan snapshot. If the
// key was reused, restore the returned value with BPF_NOEXIST; a concurrent
// replacement wins and is left untouched. Kernels without this operation rely
// on the bounded LRU maps instead of taking a racy lookup-then-delete path.
func (b *CgroupBackend) deleteStaleRedirect(
	mapFD int,
	key *listenerLookupKey,
	expected originalDestinationValue,
) (bool, error) {
	if mapFD < 0 || b.lookupAndDeleteMode.Load() == mapLookupAndDeleteUnsupported {
		return false, nil
	}
	var current originalDestinationValue
	err := lookupAndDeleteMap(mapFD, unsafe.Pointer(key), unsafe.Pointer(&current))
	if errors.Is(err, unix.ENOENT) {
		b.lookupAndDeleteMode.CompareAndSwap(mapLookupAndDeleteUnknown, mapLookupAndDeleteSupported)
		return false, nil
	}
	if err != nil {
		if mapLookupAndDeleteUnavailable(err) {
			b.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
			return false, nil
		}
		return false, err
	}
	b.lookupAndDeleteMode.CompareAndSwap(mapLookupAndDeleteUnknown, mapLookupAndDeleteSupported)
	if current == expected {
		return true, nil
	}
	if restoreErr := updateMapWithFlags(
		mapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(&current),
		bpfNoExist,
	); restoreErr != nil && !errors.Is(restoreErr, unix.EEXIST) {
		return false, E.Cause(restoreErr, "restore concurrently refreshed redirect")
	}
	return false, nil
}

// connectedUDPTokenScanBudget caps the by-value token search so it cannot
// monopolise the UDP read loop.
const connectedUDPTokenScanBudget = 4096

type tcpRedirectEntry struct {
	key   listenerLookupKey
	value originalDestinationValue
}

func (b *CgroupBackend) SweepStaleTCPRedirects(
	maxAge time.Duration,
	fallbackBudget uint32,
) (CgroupTCPRedirectSweepResult, error) {
	if b == nil {
		return CgroupTCPRedirectSweepResult{}, errBackendClosed
	}
	if maxAge <= 0 || fallbackBudget == 0 {
		return CgroupTCPRedirectSweepResult{}, unix.EINVAL
	}
	b.tcpSweepAccess.Lock()
	defer b.tcpSweepAccess.Unlock()

	nowNS, err := monotonicNowNS()
	if err != nil {
		return CgroupTCPRedirectSweepResult{}, err
	}
	maxAgeNS := uint64(maxAge)
	if nowNS <= maxAgeNS {
		return CgroupTCPRedirectSweepResult{
			Usage:    MapUsage{Capacity: b.mapCapacity.TCPRedirect},
			Complete: true,
		}, nil
	}
	staleBefore := nowNS - maxAgeNS

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return CgroupTCPRedirectSweepResult{}, errBackendClosed
	}
	b.tcpSweepCandidates = b.tcpSweepCandidates[:0]
	scan, err := b.tcpSweepScratch.scan(
		b.runtime.maps["cgroup_tcp_redirect"],
		b.mapCapacity.TCPRedirect,
		fallbackBudget,
		func(key listenerLookupKey, value originalDestinationValue) {
			if value.CreatedAtNS != 0 && value.CreatedAtNS <= staleBefore {
				b.tcpSweepCandidates = append(b.tcpSweepCandidates, tcpRedirectEntry{key: key, value: value})
			}
		},
	)
	if err != nil {
		return CgroupTCPRedirectSweepResult{}, err
	}
	result := CgroupTCPRedirectSweepResult{
		Scanned:  scan.Scanned,
		Usage:    MapUsage{Capacity: b.mapCapacity.TCPRedirect},
		Complete: scan.Complete,
	}
	if b.tcpRedirectUsageKnown.Load() {
		result.Usage.Entries = b.tcpRedirectUsage.Load()
	}
	var sweepErr error
	for _, entry := range b.tcpSweepCandidates {
		removed, deleteErr := b.deleteStaleRedirect(b.tcpRedirectMapFD, &entry.key, entry.value)
		if deleteErr != nil {
			sweepErr = E.Errors(sweepErr, deleteErr)
		}
		if removed {
			result.Removed++
		}
	}
	b.tcpSweepRemoved += result.Removed
	if result.Complete {
		result.Usage.Entries = scan.Entries
		if b.tcpSweepRemoved >= result.Usage.Entries {
			result.Usage.Entries = 0
		} else {
			result.Usage.Entries -= b.tcpSweepRemoved
		}
		b.tcpSweepRemoved = 0
		b.tcpRedirectUsage.Store(result.Usage.Entries)
		b.tcpRedirectUsageKnown.Store(true)
	}
	return result, sweepErr
}

// SweepStaleUDPRedirects removes non-connected UDP redirect entries that were
// never observed by userspace (for example, a send-only socket that closed
// before its packet reached the inbound listener). Connected entries are
// removed only when their token still exists and points at a different
// redirect; a missing token may have been evicted from the independent LRU and
// is therefore preserved for userspace recovery.
func (b *CgroupBackend) SweepStaleUDPRedirects(
	maxAge time.Duration,
	fallbackBudget uint32,
) (CgroupUDPRedirectSweepResult, error) {
	if b == nil {
		return CgroupUDPRedirectSweepResult{}, errBackendClosed
	}
	if maxAge <= 0 || fallbackBudget == 0 {
		return CgroupUDPRedirectSweepResult{}, unix.EINVAL
	}
	b.udpSweepAccess.Lock()
	defer b.udpSweepAccess.Unlock()

	nowNS, err := monotonicNowNS()
	if err != nil {
		return CgroupUDPRedirectSweepResult{}, err
	}
	maxAgeNS := uint64(maxAge)
	if nowNS <= maxAgeNS {
		return CgroupUDPRedirectSweepResult{
			Usage:    MapUsage{Capacity: b.mapCapacity.UDPRedirect},
			Complete: true,
		}, nil
	}
	staleBefore := nowNS - maxAgeNS

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return CgroupUDPRedirectSweepResult{}, errBackendClosed
	}
	b.udpSweepCandidates = b.udpSweepCandidates[:0]
	scan, err := b.udpSweepScratch.scan(
		b.runtime.maps["cgroup_udp_redirect"],
		b.mapCapacity.UDPRedirect,
		fallbackBudget,
		func(key listenerLookupKey, value originalDestinationValue) {
			if b.staleUDPRedirectEntry(key, value, staleBefore) {
				b.udpSweepCandidates = append(b.udpSweepCandidates, tcpRedirectEntry{key: key, value: value})
			}
		},
	)
	if err != nil {
		return CgroupUDPRedirectSweepResult{}, err
	}
	result := CgroupUDPRedirectSweepResult{
		Scanned:  scan.Scanned,
		Usage:    MapUsage{Capacity: b.mapCapacity.UDPRedirect},
		Complete: scan.Complete,
	}
	var sweepErr error
	for _, entry := range b.udpSweepCandidates {
		removed, deleteErr := b.deleteStaleRedirect(b.udpRedirectMapFD, &entry.key, entry.value)
		if deleteErr != nil {
			sweepErr = E.Errors(sweepErr, deleteErr)
		}
		if !removed {
			continue
		}
		result.Removed++
		if entry.value.SocketCookie != 0 && b.udpFlowMapFD >= 0 {
			flowKey := makeUDPFlowKey(entry.value)
			if flowErr := deleteMap(b.udpFlowMapFD, unsafe.Pointer(&flowKey)); flowErr != nil && !errors.Is(flowErr, unix.ENOENT) {
				sweepErr = E.Errors(sweepErr, E.Cause(flowErr, "delete stale UDP flow cache"))
			}
		}
	}
	b.udpSweepRemoved += result.Removed
	if result.Complete {
		result.Usage.Entries = scan.Entries
		if b.udpSweepRemoved >= result.Usage.Entries {
			result.Usage.Entries = 0
		} else {
			result.Usage.Entries -= b.udpSweepRemoved
		}
		b.udpSweepRemoved = 0
	}
	return result, sweepErr
}

func staleUDPRedirect(value originalDestinationValue, staleBefore uint64) bool {
	return value.Flags&originalDestinationFlagConnectedUDP == 0 &&
		value.CreatedAtNS != 0 && value.CreatedAtNS <= staleBefore
}

func (b *CgroupBackend) staleUDPRedirectEntry(
	key listenerLookupKey,
	value originalDestinationValue,
	staleBefore uint64,
) bool {
	if staleUDPRedirect(value, staleBefore) {
		return true
	}
	return value.Flags&originalDestinationFlagConnectedUDP != 0 &&
		value.CreatedAtNS != 0 && value.CreatedAtNS <= staleBefore &&
		b.orphanedConnectedUDPRedirect(key, value)
}

func (b *CgroupBackend) orphanedConnectedUDPRedirect(key listenerLookupKey, value originalDestinationValue) bool {
	if value.Flags&originalDestinationFlagConnectedUDP == 0 || value.SocketCookie == 0 {
		return false
	}
	if b.runtime == nil || b.runtime.udp_token_map_fd < 0 {
		return false
	}
	var token listenerLookupKey
	err := lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&value.SocketCookie),
		unsafe.Pointer(&token),
	)
	// Token and redirect state live in independent bounded LRU maps. If the
	// token was evicted first, userspace cannot discover this redirect through
	// RecoverConnectedUDPOriginal, so an old entry would otherwise occupy the
	// redirect map until it filled. A fresh entry is still protected by the
	// age check in staleUDPRedirectEntry; only stale orphan state reaches here.
	return errors.Is(err, unix.ENOENT) || (err == nil && token != key)
}

func monotonicNowNS() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, err
	}
	return uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec), nil
}

func (b *CgroupBackend) RedirectMapUsage(protocol uint8) (MapUsage, error) {
	if b == nil {
		return MapUsage{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return MapUsage{}, errBackendClosed
	}
	if protocol == ProtocolTCP {
		usage := MapUsage{
			Entries:  b.tcpRedirectUsage.Load(),
			Capacity: b.mapCapacity.TCPRedirect,
		}
		if !b.tcpRedirectUsageKnown.Load() {
			return usage, unix.ENODATA
		}
		return usage, nil
	}
	mapFD, err := b.redirectMap(protocol)
	if err != nil {
		return MapUsage{}, err
	}
	entries, err := countMapEntries(
		mapFD,
		unsafe.Sizeof(listenerLookupKey{}),
		b.mapCapacity.UDPRedirect,
	)
	return MapUsage{Entries: entries, Capacity: b.mapCapacity.UDPRedirect}, err
}

func (b *CgroupBackend) LookupAndDeleteMode() string {
	if b == nil {
		return "unavailable"
	}
	switch b.lookupAndDeleteMode.Load() {
	case mapLookupAndDeleteSupported:
		return "atomic"
	case mapLookupAndDeleteUnsupported:
		// Not a fallback: there is no second code path. BPF_MAP_LOOKUP_AND_DELETE_ELEM
		// only accepts hash maps from Linux 5.14, and without it deleteStaleRedirect
		// declines to act rather than race a lookup against a concurrent refresh,
		// so reclamation on such kernels is whatever the bounded LRU maps do.
		return "unsupported_lru_only"
	default:
		return "unknown"
	}
}

func (b *CgroupBackend) DeleteRedirect(protocol uint8, listenerDestination netip.AddrPort) error {
	if b == nil {
		return errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return err
	}
	var recoveryErr error
	if protocol == ProtocolUDP && b.udpFlowMapFD >= 0 {
		var original originalDestinationValue
		lookupErr := lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
		if lookupErr == nil {
			if recoveryErr = updateMap(
				b.udpRecoveryMapFD,
				unsafe.Pointer(&key),
				unsafe.Pointer(&original),
			); recoveryErr != nil {
				b.udpRecoveryUpdateFailures.Add(1)
				recoveryErr = E.Cause(recoveryErr, "retain recoverable UDP original destination")
			}
		}
		if lookupErr == nil && original.SocketCookie != 0 {
			flowKey := makeUDPFlowKey(original)
			flowErr := deleteMap(b.udpFlowMapFD, unsafe.Pointer(&flowKey))
			if flowErr != nil && !errors.Is(flowErr, unix.ENOENT) {
				return E.Cause(flowErr, "delete UDP flow cache")
			}
		} else if lookupErr != nil && !errors.Is(lookupErr, unix.ENOENT) {
			return E.Cause(lookupErr, "lookup UDP flow cache key")
		}
	}
	err = deleteMap(redirectMap, unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "delete redirect mapping")
	}
	return recoveryErr
}

func (b *CgroupBackend) redirectMap(protocol uint8) (int, error) {
	switch protocol {
	case ProtocolTCP:
		return b.tcpRedirectMapFD, nil
	case ProtocolUDP:
		return b.udpRedirectMapFD, nil
	default:
		return -1, E.New("unsupported eBPF redirect protocol: ", protocol)
	}
}

func (b *CgroupBackend) RedirectReservationFailures(protocol uint8) (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return 0, errBackendClosed
	}
	return b.redirectReservationFailuresLocked(protocol)
}

func (b *CgroupBackend) redirectReservationFailuresLocked(protocol uint8) (uint64, error) {
	var key uint32
	switch protocol {
	case ProtocolTCP:
		key = cgroupStatTCPRedirectFailure
	case ProtocolUDP:
		key = cgroupStatUDPRedirectFailure
	default:
		return 0, unix.EPROTONOSUPPORT
	}
	var failures uint64
	if err := lookupMap(b.statsMapFD, unsafe.Pointer(&key), unsafe.Pointer(&failures)); err != nil {
		return 0, err
	}
	return failures, nil
}
