//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type udpClientTable struct {
	clientShards       [udpClientShardCount]udpClientShard
	redirectAccess     sync.Mutex
	redirectReferences map[udpRedirectReference]uint32
}

const udpClientShardCount = 16

type udpClientShard struct {
	access  sync.RWMutex
	clients map[netip.AddrPort]*udpClientState
}

type udpClientState struct {
	access               sync.RWMutex
	lastActive           time.Time
	connectedBinding     atomic.Pointer[udpRedirectBinding]
	connected            bool
	connectedDestination netip.AddrPort
	sourceMAC            net.HardwareAddr
	bindings             map[netip.AddrPort]udpRedirectBinding
	originals            map[netip.Addr]udpOriginalDestination
	replyAliasCount      uint16
}

type udpRedirectBinding struct {
	address    netip.Addr
	packetInfo []byte
	connected  bool
	reference  udpRedirectReference
	sharedFlow *ECommon.SharedNetworkFlowHandle
	replyAlias bool
	direct     bool
}

type udpRedirectReference struct {
	client  netip.AddrPort
	address netip.Addr
}

type udpRedirectRelease struct {
	reference  udpRedirectReference
	sharedFlow *ECommon.SharedNetworkFlowHandle
}

type udpOriginalDestination struct {
	original   ECommon.OriginalDestination
	sharedFlow *ECommon.SharedNetworkFlowHandle
	replyAlias bool
	direct     bool
}

const udpReplyAliasLimit = 64

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	clientState, loaded := shard.clients[client]
	shard.access.RUnlock()
	return clientState, loaded
}

func (t *udpClientTable) current(client netip.AddrPort, expectedState *udpClientState) bool {
	clientState, loaded := t.load(client)
	return loaded && clientState == expectedState
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.load(client); loaded {
		return clientState
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	return shard.loadOrCreateLocked(client)
}

func (s *udpClientShard) loadOrCreateLocked(client netip.AddrPort) *udpClientState {
	if clientState, loaded := s.clients[client]; loaded {
		return clientState
	}
	if s.clients == nil {
		s.clients = make(map[netip.AddrPort]*udpClientState)
	}
	clientState := &udpClientState{
		bindings:   make(map[netip.AddrPort]udpRedirectBinding),
		originals:  make(map[netip.Addr]udpOriginalDestination),
		lastActive: time.Now(),
	}
	s.clients[client] = clientState
	return clientState
}

func (t *udpClientTable) clientShard(client netip.AddrPort) *udpClientShard {
	port := client.Port()
	index := (port ^ port>>8) & (udpClientShardCount - 1)
	return &t.clientShards[index]
}

func (t *udpClientTable) cachedOriginal(client netip.AddrPort, redirectAddress netip.Addr) (udpOriginalDestination, bool) {
	original, _, loaded := t.cachedPacketState(client, redirectAddress)
	return original, loaded
}

func (t *udpClientTable) cachedPacketState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
) (udpOriginalDestination, bool, bool) {
	clientState, loaded := t.load(client)
	if !loaded {
		return udpOriginalDestination{}, false, false
	}
	clientState.access.RLock()
	original, loaded := clientState.originals[redirectAddress]
	if !loaded {
		clientState.access.RUnlock()
		return udpOriginalDestination{}, false, false
	}
	binding, bindingLoaded := clientState.bindings[original.original.Destination]
	bindingReady := bindingLoaded &&
		binding.address == redirectAddress &&
		binding.connected == original.original.ConnectedUDP
	clientState.access.RUnlock()
	return original, bindingReady, true
}

func (t *udpClientTable) setBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	releases, _ := t.setBindingState(
		client,
		redirectAddress,
		udpRedirectReference{address: redirectAddress},
		udpOriginalDestination{
			original: ECommon.OriginalDestination{
				Destination:  destination,
				ConnectedUDP: connected,
			},
		},
	)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *udpClientTable) setSharedBinding(
	client netip.AddrPort,
	original ECommon.OriginalDestination,
	redirectAddress netip.Addr,
	flow *ECommon.SharedNetworkFlowHandle,
) ([]udpRedirectRelease, bool) {
	return t.setBindingState(
		client,
		redirectAddress,
		udpRedirectReference{client: client, address: redirectAddress},
		udpOriginalDestination{
			original:   original,
			sharedFlow: flow,
		},
	)
}

func (t *udpClientTable) setSharedAssignmentBinding(
	client netip.AddrPort,
	original ECommon.OriginalDestination,
) ([]udpRedirectRelease, bool) {
	return t.setBindingState(
		client,
		original.Destination.Addr(),
		udpRedirectReference{},
		udpOriginalDestination{original: original, direct: true},
	)
}

func (t *udpClientTable) setSharedAssignmentReplyBinding(
	client netip.AddrPort,
	expectedState *udpClientState,
	original ECommon.OriginalDestination,
) ([]udpRedirectRelease, bool) {
	return t.setExistingBindingState(
		client,
		expectedState,
		original.Destination.Addr(),
		udpRedirectReference{},
		udpOriginalDestination{original: original, replyAlias: true, direct: true},
	)
}

func (t *udpClientTable) setExistingBindingState(
	client netip.AddrPort,
	expectedState *udpClientState,
	redirectAddress netip.Addr,
	reference udpRedirectReference,
	original udpOriginalDestination,
) ([]udpRedirectRelease, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expectedState {
		return nil, false
	}
	return t.setClientBinding(expectedState, redirectAddress, reference, original)
}

func (t *udpClientTable) setBindingState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
	reference udpRedirectReference,
	original udpOriginalDestination,
) ([]udpRedirectRelease, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	clientState, loaded := shard.clients[client]
	if loaded {
		released, installed := t.setClientBinding(clientState, redirectAddress, reference, original)
		shard.access.RUnlock()
		return released, installed
	}
	shard.access.RUnlock()

	shard.access.Lock()
	clientState = shard.loadOrCreateLocked(client)
	released, installed := t.setClientBinding(clientState, redirectAddress, reference, original)
	shard.access.Unlock()
	return released, installed
}

func (t *udpClientTable) setClientBinding(
	clientState *udpClientState,
	redirectAddress netip.Addr,
	reference udpRedirectReference,
	original udpOriginalDestination,
) ([]udpRedirectRelease, bool) {
	destination := original.original.Destination
	connected := original.original.ConnectedUDP
	clientState.access.RLock()
	current, loaded := clientState.bindings[destination]
	clientState.access.RUnlock()
	if loaded && current.address == redirectAddress && current.connected == connected &&
		current.replyAlias == original.replyAlias && current.direct == original.direct {
		return nil, false
	}

	clientState.access.Lock()
	defer clientState.access.Unlock()
	current, loaded = clientState.bindings[destination]
	clientState.lastActive = time.Now()
	if original.replyAlias && (!loaded || !current.replyAlias) && clientState.replyAliasCount >= udpReplyAliasLimit {
		return nil, false
	}
	clientState.originals[redirectAddress] = original
	if len(original.original.SourceMAC) != 0 {
		clientState.sourceMAC = append(clientState.sourceMAC[:0], original.original.SourceMAC...)
	}
	binding := udpRedirectBinding{
		address:    redirectAddress,
		packetInfo: sourcePacketInfo(redirectAddress),
		connected:  connected,
		reference:  reference,
		sharedFlow: original.sharedFlow,
		replyAlias: original.replyAlias,
		direct:     original.direct,
	}
	clientState.bindings[destination] = binding
	if original.replyAlias && (!loaded || !current.replyAlias) {
		clientState.replyAliasCount++
	} else if !original.replyAlias && loaded && current.replyAlias {
		clientState.replyAliasCount--
	}
	if clientState.connected && clientState.connectedDestination == destination {
		connectedBinding := binding
		clientState.connectedBinding.Store(&connectedBinding)
	}
	if loaded && current.address != redirectAddress {
		clientState.deleteUnusedOriginalLocked(current.address)
	}

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	if !connected && !binding.direct {
		t.retainRedirectLocked(reference)
	}
	if loaded && !current.connected && !current.direct && t.releaseRedirectLocked(current.reference) {
		return []udpRedirectRelease{{
			reference:  current.reference,
			sharedFlow: current.sharedFlow,
		}}, true
	}
	return nil, true
}

func (s *udpClientState) deleteUnusedOriginalLocked(address netip.Addr) {
	for _, binding := range s.bindings {
		if binding.address == address {
			return
		}
	}
	delete(s.originals, address)
}

func (t *udpClientTable) delete(client netip.AddrPort, expectedState *udpClientState) []netip.Addr {
	releases := t.deleteClient(client, expectedState)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

// deleteShared releases a shared-network client's bindings, returning the TC
// flow handles to release.
func (t *udpClientTable) deleteShared(client netip.AddrPort, expectedState *udpClientState) []udpRedirectRelease {
	return t.deleteClient(client, expectedState)
}

func (t *udpClientTable) deleteClient(client netip.AddrPort, expectedState *udpClientState) []udpRedirectRelease {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expectedState {
		return nil
	}
	delete(shard.clients, client)

	expectedState.access.Lock()
	defer expectedState.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	var released []udpRedirectRelease
	for _, binding := range expectedState.bindings {
		if !binding.connected && !binding.direct && t.releaseRedirectLocked(binding.reference) {
			released = append(released, udpRedirectRelease{
				reference:  binding.reference,
				sharedFlow: binding.sharedFlow,
			})
		}
	}
	clear(expectedState.bindings)
	clear(expectedState.originals)
	expectedState.replyAliasCount = 0
	expectedState.connectedBinding.Store(nil)
	return released
}

// sweep removes client states that have been idle for longer than timeout and
// passes their released bindings to release. The caller decides whether to
// delete cgroup redirect entries or shared-network TC flow handles.
func (t *udpClientTable) sweep(now time.Time, timeout time.Duration, release func(releases []udpRedirectRelease)) {
	var clients []*udpClientState
	for index := range t.clientShards {
		shard := &t.clientShards[index]
		shard.access.RLock()
		for _, clientState := range shard.clients {
			clientState.access.RLock()
			idle := now.Sub(clientState.lastActive)
			clientState.access.RUnlock()
			if idle > timeout {
				clients = append(clients, clientState)
			}
		}
		shard.access.RUnlock()
	}
	for _, clientState := range clients {
		releases := t.deleteClientByState(clientState)
		release(releases)
	}
}

func (t *udpClientTable) deleteClientByState(expectedState *udpClientState) []udpRedirectRelease {
	for index := range t.clientShards {
		shard := &t.clientShards[index]
		shard.access.Lock()
		for client, state := range shard.clients {
			if state == expectedState {
				delete(shard.clients, client)
				shard.access.Unlock()
				return t.releaseClientState(expectedState)
			}
		}
		shard.access.Unlock()
	}
	return nil
}

func (t *udpClientTable) releaseClientState(expectedState *udpClientState) []udpRedirectRelease {
	expectedState.access.Lock()
	defer expectedState.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	var released []udpRedirectRelease
	for _, binding := range expectedState.bindings {
		if !binding.connected && !binding.direct && t.releaseRedirectLocked(binding.reference) {
			released = append(released, udpRedirectRelease{
				reference:  binding.reference,
				sharedFlow: binding.sharedFlow,
			})
		}
	}
	clear(expectedState.bindings)
	clear(expectedState.originals)
	expectedState.replyAliasCount = 0
	expectedState.connectedBinding.Store(nil)
	return released
}

func (t *udpClientTable) retainRedirectLocked(reference udpRedirectReference) {
	if t.redirectReferences == nil {
		t.redirectReferences = make(map[udpRedirectReference]uint32)
	}
	t.redirectReferences[reference]++
}

func (t *udpClientTable) releaseRedirectLocked(reference udpRedirectReference) bool {
	references := t.redirectReferences[reference]
	if references > 1 {
		t.redirectReferences[reference] = references - 1
		return false
	}
	if references == 1 {
		delete(t.redirectReferences, reference)
		return true
	}
	return false
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	if binding := s.connectedBinding.Load(); binding != nil {
		return *binding, true
	}
	s.access.RLock()
	if s.connected {
		destination = s.connectedDestination
	}
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

// replyTemplate returns an existing binding of the matching address family to
// derive a reply alias from when a direct lookup misses.
func (s *udpClientState) replyTemplate(destination netip.AddrPort, shared bool) (udpRedirectBinding, bool) {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return udpRedirectBinding{}, false
	}
	for _, binding := range s.bindings {
		if binding.address.Is4() == destination.Addr().Is4() && (!shared || binding.sharedFlow != nil) {
			return binding, true
		}
	}
	return udpRedirectBinding{}, false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}

func (s *udpClientState) setConnected(connected bool, destination netip.AddrPort) {
	s.access.Lock()
	s.connected = connected
	if connected {
		s.connectedDestination = destination
		if binding, loaded := s.bindings[destination]; loaded {
			connectedBinding := binding
			s.connectedBinding.Store(&connectedBinding)
		} else {
			s.connectedBinding.Store(nil)
		}
	} else {
		s.connectedDestination = netip.AddrPort{}
		s.connectedBinding.Store(nil)
	}
	s.access.Unlock()
}

func (s *udpClientState) isConnected() bool {
	s.access.RLock()
	connected := s.connected
	s.access.RUnlock()
	return connected
}
