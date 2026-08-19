//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"time"
	"unsafe"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (b *SharedNetworkBackend) LookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, error) {
	original, _, err := b.lookupFlow(protocol, client, tokenDestination, false)
	return original, err
}

func (b *SharedNetworkBackend) LookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	return b.lookupFlow(protocol, client, tokenDestination, true)
}

func (b *SharedNetworkBackend) lookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
	retain bool,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	if b == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	key, err := makeSharedNetworkListenerKey(protocol, client, tokenDestination)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	if retain {
		b.flowAccess.Lock()
		defer b.flowAccess.Unlock()
	}
	var value sharedNetworkOriginalValue
	if err = lookupMap(
		int(b.runtime.listener_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return OriginalDestination{}, nil, E.Cause(err, "lookup shared-network original destination")
	}
	address, err := sharedNetworkOriginalAddress(value)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	flow := makeSharedNetworkFlowHandle(key, value)
	if retain {
		b.retainFlowLocked(flow)
	}
	return OriginalDestination{
		Destination: netip.AddrPortFrom(address, value.Port),
		SourceMAC:   sharedNetworkOriginalMAC(value),
	}, &flow, nil
}

func (b *SharedNetworkBackend) ReserveUDPReplyFlow(
	base *SharedNetworkFlowHandle,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
) (netip.Addr, *SharedNetworkFlowHandle, error) {
	if b == nil {
		return netip.Addr{}, nil, errBackendClosed
	}
	if base == nil || base.originalKey.Protocol != ProtocolUDP {
		return netip.Addr{}, nil, E.New("missing shared-network UDP base flow")
	}
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().IsUnspecified() {
		return netip.Addr{}, nil, E.New("invalid shared-network UDP reply source: ", destination)
	}
	originalKey := base.originalKey
	originalKey.OriginalPort = destination.Port()
	var destinationFamily uint8
	if err := encodeAddress(&destinationFamily, &originalKey.OriginalAddr, destination.Addr()); err != nil {
		return netip.Addr{}, nil, E.Cause(err, "encode shared-network UDP reply source")
	}
	if destinationFamily != originalKey.Family {
		return netip.Addr{}, nil, E.New("shared-network UDP reply source family changed: ", destination)
	}

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return netip.Addr{}, nil, errBackendClosed
	}
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if token, flow, loaded, err := b.lookupUDPReplyFlowLocked(originalKey); loaded || err != nil {
		return token, flow, err
	}

	prefix, err := b.udpReplyTokenPrefix(originalKey.Family)
	if err != nil {
		return netip.Addr{}, nil, err
	}
	var now unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return netip.Addr{}, nil, E.Cause(err, "read monotonic clock for shared-network UDP reply")
	}
	nowNS := uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
	originalValue := sharedNetworkOriginalValue{
		Family:         originalKey.Family,
		Protocol:       ProtocolUDP,
		Port:           destination.Port(),
		Addr:           originalKey.OriginalAddr,
		InterfaceIndex: originalKey.InterfaceIndex,
	}
	copy(originalValue.SourceMAC[:], sourceMAC)
	replyValue := sharedNetworkReplyValue{
		OriginalPort: destination.Port(),
		OriginalAddr: originalKey.OriginalAddr,
	}

	for attempt := 0; attempt < userspaceReplyTokenAttempts; {
		sequence := b.replyTokenSequence.Add(1)
		token, valid := userspaceReplyToken(prefix, sequence)
		if !valid {
			continue
		}
		attempt++
		var tokenAddress [16]byte
		var tokenFamily uint8
		if err = encodeAddress(&tokenFamily, &tokenAddress, token); err != nil {
			return netip.Addr{}, nil, err
		}
		if tokenFamily != originalKey.Family {
			return netip.Addr{}, nil, E.New("shared-network UDP reply token family mismatch")
		}
		flow := makeSharedNetworkFlowHandleFromOriginal(originalKey, tokenAddress, b.control.ListenerPort)
		err = updateMapWithFlags(
			int(b.runtime.listener_map_fd),
			unsafe.Pointer(&flow.listenerKey),
			unsafe.Pointer(&originalValue),
			bpfNoExist,
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return netip.Addr{}, nil, E.Cause(err, "reserve shared-network UDP reply listener token")
		}
		if err = updateMap(
			int(b.runtime.reply_map_fd),
			unsafe.Pointer(&flow.replyKey),
			unsafe.Pointer(&replyValue),
		); err != nil {
			cleanupErr := deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey))
			return netip.Addr{}, nil, E.Errors(E.Cause(err, "reserve shared-network UDP reply state"), cleanupErr)
		}
		tokenValue := sharedNetworkTokenValue{
			TokenAddr:   tokenAddress,
			Generation:  nowNS ^ sequence,
			CreatedAtNS: nowNS,
			LastSeenNS:  nowNS,
		}
		err = updateMapWithFlags(
			int(b.runtime.original_to_token_map_fd),
			unsafe.Pointer(&flow.originalKey),
			unsafe.Pointer(&tokenValue),
			bpfNoExist,
		)
		if err != nil {
			cleanupErr := E.Errors(
				deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
				deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
			)
			if errors.Is(err, unix.EEXIST) {
				existingToken, existingFlow, loaded, lookupErr := b.lookupUDPReplyFlowLocked(originalKey)
				if lookupErr != nil {
					return netip.Addr{}, nil, E.Errors(lookupErr, cleanupErr)
				}
				if cleanupErr != nil {
					if loaded {
						b.releaseFlowReferenceLocked(*existingFlow)
					}
					return netip.Addr{}, nil, cleanupErr
				}
				if loaded {
					return existingToken, existingFlow, nil
				}
				continue
			}
			return netip.Addr{}, nil, E.Errors(E.Cause(err, "reserve shared-network UDP reply flow"), cleanupErr)
		}
		b.retainFlowLocked(flow)
		return token, &flow, nil
	}
	return netip.Addr{}, nil, E.New("reserve shared-network UDP reply flow: token attempts exhausted")
}

func (b *SharedNetworkBackend) lookupUDPReplyFlowLocked(
	originalKey sharedNetworkOriginalKey,
) (netip.Addr, *SharedNetworkFlowHandle, bool, error) {
	var value sharedNetworkTokenValue
	if err := lookupMap(
		int(b.runtime.original_to_token_map_fd),
		unsafe.Pointer(&originalKey),
		unsafe.Pointer(&value),
	); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return netip.Addr{}, nil, false, nil
		}
		return netip.Addr{}, nil, false, E.Cause(err, "lookup shared-network UDP reply flow")
	}
	token, err := sharedNetworkAddress(originalKey.Family, value.TokenAddr)
	if err != nil {
		return netip.Addr{}, nil, false, err
	}
	flow := makeSharedNetworkFlowHandleFromOriginal(originalKey, value.TokenAddr, b.control.ListenerPort)
	b.retainFlowLocked(flow)
	return token, &flow, true, nil
}

func (b *SharedNetworkBackend) udpReplyTokenPrefix(family uint8) (netip.Prefix, error) {
	switch family {
	case addressFamilyIPv4:
		if b.control.Flags&sharedNetworkFlagIPv4 == 0 {
			break
		}
		return netip.PrefixFrom(
			netip.AddrFrom4(b.control.TokenIPv4Prefix),
			int(b.control.TokenIPv4PrefixBits),
		).Masked(), nil
	case addressFamilyIPv6:
		if b.control.Flags&sharedNetworkFlagIPv6 == 0 {
			break
		}
		return netip.PrefixFrom(
			netip.AddrFrom16(b.control.TokenIPv6Prefix),
			int(b.control.TokenIPv6PrefixBits),
		).Masked(), nil
	}
	return netip.Prefix{}, E.New("shared-network UDP reply address family is not enabled: ", family)
}

func (b *SharedNetworkBackend) ReleaseFlow(flow *SharedNetworkFlowHandle) error {
	if b == nil || flow == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if !b.releaseFlowReferenceLocked(*flow) {
		return nil
	}
	return E.Errors(
		deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
		deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
		deleteMapIfExists(int(b.runtime.original_to_token_map_fd), unsafe.Pointer(&flow.originalKey)),
	)
}

func (b *SharedNetworkBackend) retainFlowLocked(flow SharedNetworkFlowHandle) {
	if b.flowReferences == nil {
		b.flowReferences = make(map[SharedNetworkFlowHandle]uint32)
	}
	b.flowReferences[flow]++
}

func (b *SharedNetworkBackend) releaseFlowReferenceLocked(flow SharedNetworkFlowHandle) bool {
	references := b.flowReferences[flow]
	if references == 0 {
		return false
	}
	if references > 1 {
		b.flowReferences[flow] = references - 1
		return false
	}
	delete(b.flowReferences, flow)
	return true
}

type sharedNetworkFlowEntry struct {
	key   sharedNetworkOriginalKey
	value sharedNetworkTokenValue
}

func (b *SharedNetworkBackend) SweepOrphanedFlows(
	maxIdle time.Duration,
	fallbackBudget uint32,
) (SharedNetworkFlowSweepResult, error) {
	if b == nil {
		return SharedNetworkFlowSweepResult{}, errBackendClosed
	}
	if maxIdle <= 0 || fallbackBudget == 0 {
		return SharedNetworkFlowSweepResult{}, unix.EINVAL
	}
	b.flowSweepAccess.Lock()
	defer b.flowSweepAccess.Unlock()

	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return SharedNetworkFlowSweepResult{}, err
	}
	nowNS := uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
	maxIdleNS := uint64(maxIdle)
	if nowNS <= maxIdleNS {
		return SharedNetworkFlowSweepResult{
			Usage:    MapUsage{Capacity: b.mapCapacity.Proxy},
			Complete: true,
		}, nil
	}
	staleBefore := nowNS - maxIdleNS

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return SharedNetworkFlowSweepResult{}, errBackendClosed
	}
	mapFD := int(b.runtime.original_to_token_map_fd)
	b.flowSweepCandidates = b.flowSweepCandidates[:0]
	scan, err := b.flowSweepScratch.scan(
		b.runtime.maps["shared_original_to_token"],
		b.mapCapacity.Proxy,
		fallbackBudget,
		func(key sharedNetworkOriginalKey, value sharedNetworkTokenValue) {
			if value.LastSeenNS != 0 && value.LastSeenNS <= staleBefore {
				b.flowSweepCandidates = append(
					b.flowSweepCandidates,
					sharedNetworkFlowEntry{key: key, value: value},
				)
			}
		},
	)
	if err != nil {
		return SharedNetworkFlowSweepResult{}, err
	}
	result := SharedNetworkFlowSweepResult{
		Scanned:  scan.Scanned,
		Usage:    MapUsage{Capacity: b.mapCapacity.Proxy},
		Complete: scan.Complete,
	}
	if b.proxyUsageKnown.Load() {
		result.Usage.Entries = b.proxyUsage.Load()
	}
	var sweepErr error
	for _, entry := range b.flowSweepCandidates {
		removed, retained, removeErr := b.removeOrphanedFlowCandidate(mapFD, entry)
		if retained {
			result.Retained++
		}
		if removeErr != nil {
			sweepErr = E.Errors(sweepErr, removeErr)
			continue
		}
		if removed {
			result.Removed++
		}
	}
	b.flowSweepRemoved += result.Removed
	if result.Complete {
		result.Usage.Entries = scan.Entries
		if b.flowSweepRemoved >= result.Usage.Entries {
			result.Usage.Entries = 0
		} else {
			result.Usage.Entries -= b.flowSweepRemoved
		}
		b.flowSweepRemoved = 0
		b.proxyUsage.Store(result.Usage.Entries)
		b.proxyUsageKnown.Store(true)
	}
	return result, sweepErr
}

func (b *SharedNetworkBackend) removeOrphanedFlowCandidate(
	mapFD int,
	entry sharedNetworkFlowEntry,
) (removed bool, retained bool, err error) {
	flow := makeSharedNetworkFlowHandleFromOriginal(
		entry.key,
		entry.value.TokenAddr,
		b.control.ListenerPort,
	)
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if b.flowReferences[flow] > 0 {
		return false, true, nil
	}
	var current sharedNetworkTokenValue
	if err = lookupMap(mapFD, unsafe.Pointer(&entry.key), unsafe.Pointer(&current)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, false, nil
		}
		return false, false, err
	}
	if current != entry.value {
		return false, false, nil
	}
	err = E.Errors(
		deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
		deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
		deleteMapIfExists(mapFD, unsafe.Pointer(&flow.originalKey)),
	)
	return err == nil, false, err
}

func (b *SharedNetworkBackend) ProxyMapUsage() (MapUsage, error) {
	if b == nil {
		return MapUsage{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return MapUsage{}, errBackendClosed
	}
	usage := MapUsage{
		Entries:  b.proxyUsage.Load(),
		Capacity: b.mapCapacity.Proxy,
	}
	if !b.proxyUsageKnown.Load() {
		return usage, unix.ENODATA
	}
	return usage, nil
}

func deleteMapIfExists(mapFD int, key unsafe.Pointer) error {
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *SharedNetworkBackend) TokenReservationFailures() (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return 0, errBackendClosed
	}
	key := uint32(sharedNetworkStatTokenReservationFailure)
	var failures uint64
	if err := lookupMap(b.statsMapFD, unsafe.Pointer(&key), unsafe.Pointer(&failures)); err != nil {
		return 0, err
	}
	return failures, nil
}
