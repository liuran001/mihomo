//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHijackDNS(t *testing.T) {
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	other := netip.MustParseAddrPort("8.8.8.8:443")

	inbound := &Inbound{dnsMode: dnsModeHijack}
	if !inbound.hijackDNS(dns) {
		t.Fatal("expected port 53 to be hijacked in hijack mode")
	}
	if inbound.hijackDNS(other) {
		t.Fatal("expected non-53 traffic not to be hijacked")
	}

	offbound := &Inbound{dnsMode: dnsModeOff}
	if offbound.hijackDNS(dns) {
		t.Fatal("expected no hijack in off mode")
	}
}

func TestSourcePacketInfo(t *testing.T) {
	ipv4 := netip.MustParseAddr("127.128.0.1")
	info := sourcePacketInfo(ipv4)
	if len(info) < unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo {
		t.Fatalf("unexpected IPv4 packet info length: %d", len(info))
	}

	ipv6 := netip.MustParseAddr("fd53:696e:672d:626f::1")
	info6 := sourcePacketInfo(ipv6)
	if len(info6) < unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo {
		t.Fatalf("unexpected IPv6 packet info length: %d", len(info6))
	}
}
