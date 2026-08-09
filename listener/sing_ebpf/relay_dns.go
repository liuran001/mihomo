//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/resolver"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

// hijackDNS reports whether a restored destination should be handled by
// mihomo's own DNS resolver pipeline instead of being routed like a normal
// connection. With dns-mode: hijack the kernel programs already redirect port
// 53 into the internal listeners, so the inbound only needs to hand the query
// straight to the resolver service (the same pipeline behind dns.listen and
// the type: dns outbound) and write the reply back through the redirect path.
func (i *Inbound) hijackDNS(destination netip.AddrPort) bool {
	return i.dnsMode == dnsModeHijack && destination.Port() == 53
}

func (i *Inbound) relayTCPDNS(conn net.Conn) {
	if err := resolver.RelayDnsConn(context.Background(), conn, resolver.DefaultDnsReadTimeout); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "relay hijacked TCP DNS: ", err)
	}
}

func (i *Inbound) relayUDPDNS(data []byte, client netip.AddrPort, clientState *udpClientState, destination netip.AddrPort) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDnsRelayTimeout)
	defer cancel()
	buff := make([]byte, resolver.SafeDnsPacketSize)
	reply, err := resolver.RelayDnsPacket(ctx, data, buff)
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logWarn, "relay hijacked UDP DNS: ", err)
		return
	}
	binding, loaded := clientState.redirectBinding(destination)
	if !loaded {
		i.udpWarnings.originalDestination.warn(i.logWarn, "missing UDP DNS binding for ", client)
		return
	}
	udpConn := i.listeners.udpConn(binding.address.Is6())
	if udpConn == nil {
		i.udpWarnings.originalDestination.warn(i.logWarn, "eBPF UDP DNS listener is unavailable")
		return
	}
	if _, _, err = udpConn.WriteMsgUDPAddrPort(reply, binding.packetInfo, client); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "write hijacked UDP DNS reply: ", err)
	}
}

func (s *sharedNetwork) relayTCPDNS(conn net.Conn, flow *ECommon.SharedNetworkFlowHandle) {
	defer s.releaseFlow(flow)
	if err := resolver.RelayDnsConn(context.Background(), conn, resolver.DefaultDnsReadTimeout); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "relay hijacked TCP DNS: ", err)
	}
}

func (s *sharedNetwork) relayUDPDNS(data []byte, client netip.AddrPort, clientState *udpClientState, destination netip.AddrPort) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDnsRelayTimeout)
	defer cancel()
	buff := make([]byte, resolver.SafeDnsPacketSize)
	reply, err := resolver.RelayDnsPacket(ctx, data, buff)
	if err != nil {
		s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "relay hijacked UDP DNS: ", err)
		return
	}
	binding, loaded := clientState.redirectBinding(destination)
	if !loaded {
		s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "missing shared-network UDP DNS binding for ", client)
		return
	}
	if err = s.listeners.writeUDP(reply, binding.packetInfo, client, binding.address); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "write hijacked UDP DNS reply: ", err)
	}
}
