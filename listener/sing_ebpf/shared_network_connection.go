//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (s *sharedNetwork) NewConnection(conn net.Conn) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	client, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	tokenDestination, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	// Socket-assignment data plane: the kernel steered the flow into the
	// internal listener with the ORIGINAL destination preserved, so
	// tokenDestination already is the real destination.
	if backend.TCPAssignmentEnabled() && !s.inbound.isRedirectListenerDestination(tokenDestination, s.listeners.selectedPort()) {
		_, _, metadataErr := backend.TakeTCPAssignmentMetadata(client, tokenDestination)
		if metadataErr != nil && !errors.Is(metadataErr, unix.ENOENT) {
			s.udpWarnings.cleanup.warn(s.inbound.logWarn, "lookup shared-network TCP assignment metadata: ", metadataErr)
			_ = conn.Close()
			return
		}
		s.inbound.handleTCPTunnel(conn, client, tokenDestination)
		return
	}
	original, flow, err := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
	if errors.Is(err, unix.ENOENT) {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "missing shared-network TCP redirect state for ", client)
		s.inbound.wakeTCPRedirectJanitor()
		_ = conn.Close()
		return
	}
	if err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "lookup shared-network TCP original destination: ", err)
		_ = conn.Close()
		return
	}
	if s.inbound.hijackDNS(original.Destination) {
		go s.relayTCPDNS(conn, flow)
		return
	}
	s.inbound.handleSharedTCPConn(conn, client, original.Destination, flow)
}

func (s *sharedNetwork) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	// Same pooled-buffer contract as Inbound.NewPacket: release on every path
	// that does not reach HandleUDPPacket.
	handedOff := false
	defer func() {
		if !handedOff {
			_ = pool.Put(data)
		}
	}()
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	tokenAddress, packetDestination, hasPacketDestination, err := func() (netip.Addr, netip.AddrPort, bool, error) {
		token, destination, parseErr := packetDestinationsFromOOB(oob)
		if parseErr != nil {
			return netip.Addr{}, netip.AddrPort{}, false, parseErr
		}
		if destination.Port() == 0 {
			destination = netip.AddrPortFrom(destination.Addr(), s.listeners.selectedPort())
		}
		return token, destination, destination.IsValid(), nil
	}()
	if err != nil {
		s.udpWarnings.packetInfo.warn(s.inbound.logWarn, "read shared-network UDP token address: ", err)
		return
	}
	client := source
	// Socket-assignment data plane: the original destination arrives in the
	// packet info and the flow state lives in the assignment metadata map.
	if backend.UDPAssignmentEnabled() && hasPacketDestination &&
		!s.inbound.isRedirectListenerDestination(packetDestination, s.listeners.selectedPort()) {
		_, sourceMACValue, metadataErr := backend.LookupUDPAssignmentMetadata(client, packetDestination)
		if metadataErr != nil {
			s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "lookup shared-network UDP assignment metadata: ", metadataErr)
			return
		}
		sourceMAC := net.HardwareAddr(sourceMACValue[:])
		original := ECommon.OriginalDestination{
			Destination: packetDestination,
			SourceMAC:   sourceMAC,
		}
		released, _ := s.udpClientTable.setSharedAssignmentBinding(client, original)
		s.releaseFlows(released)
		handedOff = s.forwardUDPPacket(data, client, original.Destination, false)
		return
	}
	tokenDestination := netip.AddrPortFrom(tokenAddress, s.listeners.selectedPort())
	cached, bindingReady, loaded := s.udpClientTable.cachedPacketState(client, tokenAddress)
	var cachedOriginal ECommon.OriginalDestination
	flow := cached.sharedFlow
	retainedFlow := false
	if !loaded {
		cachedOriginal, flow, err = backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
		if err != nil {
			s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "lookup shared-network UDP original destination: ", err)
			return
		}
		retainedFlow = true
	}
	if !bindingReady {
		released, installed := s.udpClientTable.setSharedBinding(
			client,
			cachedOriginal,
			tokenAddress,
			flow,
		)
		if retainedFlow && !installed {
			s.releaseFlow(flow)
		}
		s.releaseFlows(released)
	}

	clientState := s.udpClientTable.loadOrCreate(client)
	if s.inbound.hijackDNS(cachedOriginal.Destination) {
		s.relayUDPDNS(data, client, clientState, cachedOriginal.Destination)
		return
	}
	handedOff = s.forwardUDPPacket(data, client, cachedOriginal.Destination, cachedOriginal.ConnectedUDP)
}

// forwardUDPPacket hands the pooled buffer to the tunnel and reports that
// ownership moved, so NewPacket stops releasing it. The tunnel calls Drop on
// every outcome it has, including a full queue and a closed sender.
func (s *sharedNetwork) forwardUDPPacket(data []byte, client netip.AddrPort, destination netip.AddrPort, connected bool) bool {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, s.inbound.additions...)

	clientState := s.udpClientTable.loadOrCreate(client)
	clientState.setConnected(connected, destination)
	packet := &sharedPacket{
		shared:      s,
		client:      client,
		clientState: clientState,
		data:        data,
		lAddr:       N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client)),
	}
	s.inbound.tunnel.HandleUDPPacket(packet, metadata)
	return true
}

// handleTCPTunnel routes a shared-network TCP connection whose destination is
// already the real target (socket-assignment data plane).
func (i *Inbound) handleTCPTunnel(conn net.Conn, client netip.AddrPort, destination netip.AddrPort) {
	if i.hijackDNS(destination) {
		go i.relayTCPDNS(conn)
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

// handleSharedTCPConn routes a rewrite-path TCP connection and releases the
// TC flow handle when the connection closes.
func (i *Inbound) handleSharedTCPConn(conn net.Conn, client netip.AddrPort, destination netip.AddrPort, flow *ECommon.SharedNetworkFlowHandle) {
	if s := i.sharedNetwork; s != nil {
		wrapped := &sharedConn{Conn: conn, shared: s, flow: flow}
		conn = wrapped
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

func (s *sharedNetwork) releaseFlows(releases []udpRedirectRelease) {
	for _, release := range releases {
		s.releaseFlow(release.sharedFlow)
	}
}

func (s *sharedNetwork) releaseFlow(flow *ECommon.SharedNetworkFlowHandle) {
	if flow == nil {
		return
	}
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	if err := backend.ReleaseFlow(flow); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "release shared-network flow: ", err)
	}
}

type sharedConn struct {
	net.Conn
	shared *sharedNetwork
	flow   *ECommon.SharedNetworkFlowHandle
	once   sync.Once
}

func (c *sharedConn) Close() error {
	c.once.Do(func() {
		c.shared.releaseFlow(c.flow)
	})
	return c.Conn.Close()
}

type sharedPacket struct {
	shared      *sharedNetwork
	client      netip.AddrPort
	clientState *udpClientState
	data        []byte
	lAddr       net.Addr
}

func (p *sharedPacket) Data() []byte {
	return p.data
}

func (p *sharedPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	destination, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("invalid UDP reply address")
	}
	p.shared.lifecycleAccess.RLock()
	defer p.shared.lifecycleAccess.RUnlock()
	if p.clientState == nil {
		return 0, E.New("missing shared-network UDP state for ", p.client)
	}
	destinationAddress := destination.AddrPort()
	binding, loaded := p.clientState.redirectBinding(destinationAddress)
	if !loaded {
		var reserveErr error
		binding, reserveErr = p.reserveReplyBinding(destinationAddress)
		if reserveErr != nil {
			return 0, E.Cause(reserveErr, "recover missing shared-network UDP token for ", destinationAddress)
		}
	}
	if err := p.shared.listeners.writeUDP(b, binding.packetInfo, p.client, binding.address); err != nil {
		return 0, err
	}
	return len(b), nil
}

// reserveReplyBinding recovers a missing reply binding by aliasing an existing
// same-family binding; direct (socket-assigned) flows install a direct reply
// alias so replies leave through the assigned path as well.
func (p *sharedPacket) reserveReplyBinding(destination netip.AddrPort) (udpRedirectBinding, error) {
	template, loaded := p.clientState.replyTemplate(destination, true)
	if !loaded {
		template, loaded = p.clientState.replyTemplate(destination, false)
	}
	if !loaded || !template.direct {
		// Rewrite-path flows always have an explicit binding; a miss here is
		// a late reply after the client entry was dropped.
		return udpRedirectBinding{}, E.New("shared-network UDP binding for ", destination)
	}
	sourceMAC := p.clientState.sourceMACAddress()
	released, installed := p.shared.udpClientTable.setSharedAssignmentReplyBinding(
		p.client,
		p.clientState,
		ECommon.OriginalDestination{Destination: destination, SourceMAC: sourceMAC},
	)
	p.shared.releaseFlows(released)
	if !installed {
		return udpRedirectBinding{}, E.New("shared-network UDP direct reply alias was rejected")
	}
	binding, _ := p.clientState.redirectBinding(destination)
	return binding, nil
}

func (p *sharedPacket) Drop() {
	_ = pool.Put(p.data)
	p.data = nil
}

func (p *sharedPacket) LocalAddr() net.Addr {
	return p.lAddr
}

var _ C.UDPPacket = (*sharedPacket)(nil)
