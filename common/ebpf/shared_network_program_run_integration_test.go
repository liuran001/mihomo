//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	testEthernetHeaderLength = 14
	testIPv4HeaderLength     = 20
	testTCPHeaderLength      = 20
	testUDPHeaderLength      = 8
	testTCActOK              = uint32(0)
	testTCActShot            = uint32(2)
	testTCActUnspec          = ^uint32(0)
)

func TestSharedNetworkProgramRunIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run shared-network programs in the kernel")
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
		ListenerPort:         65531,
		EnableTCP:            true,
		EnableUDP:            true,
		DNSMode:              DNSModeRespectPolicy,
		BypassPrivateAddress: true,
		RedirectIPv4:         netip.MustParsePrefix("127.128.0.0/9"),
		FakeIPIPv4:           netip.MustParsePrefix("198.18.0.0/15"),
		MapCapacity:          DefaultSharedNetworkMapCapacities(),
		UDPTimeout:           5 * time.Minute,
		DataPlane:            SharedNetworkDataPlaneRewrite,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	ingress := backend.runtime.programs[sharedNetworkProgramIngress]

	t.Run("policy_priority", func(t *testing.T) {
		privateDNS := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.168.1.1"), 53000, 53,
		)
		action, output := runSharedNetworkProgram(t, ingress, privateDNS)
		if action != testTCActUnspec || string(output) != string(privateDNS) {
			t.Fatalf("respect_policy did not bypass private DNS: action=%d", action)
		}

		backend.control.DNSMode = DNSModeHijack
		if err := backend.updateControl(); err != nil {
			t.Fatal(err)
		}
		action, output = runSharedNetworkProgram(t, ingress, privateDNS)
		if action != testTCActOK {
			t.Fatalf("hijack DNS was not rewritten: action=%d", action)
		}
		assertIPv4TCPRewrite(t, output, netip.MustParseAddr("127.128.0.0"), 9, 65531)

		backend.control.DNSMode = DNSModeRespectPolicy
		if err := backend.updateControl(); err != nil {
			t.Fatal(err)
		}
		fakeIP := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53001, 443,
		)
		action, output = runSharedNetworkProgram(t, ingress, fakeIP)
		if action != testTCActOK {
			t.Fatalf("FakeIP was not prioritized over private bypass: action=%d", action)
		}
		assertIPv4TCPRewrite(t, output, netip.MustParseAddr("127.128.0.0"), 9, 65531)
	})

	t.Run("fragment_state", func(t *testing.T) {
		first := testIPv4UDPFragment(
			netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("203.0.113.20"),
			54000, 443, 0x4242, 0, true, []byte("first-fragment"),
		)
		action, firstOut := runSharedNetworkProgram(t, ingress, first)
		if action != testTCActOK {
			t.Fatalf("first fragment was not rewritten: action=%d", action)
		}
		token := netip.AddrFrom4([4]byte(firstOut[30:34]))

		later := testIPv4UDPFragment(
			netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("203.0.113.20"),
			0, 0, 0x4242, 2, false, []byte("later-fragment"),
		)
		action, laterOut := runSharedNetworkProgram(t, ingress, later)
		if action != testTCActOK {
			t.Fatalf("known later fragment was not rewritten: action=%d", action)
		}
		if got := netip.AddrFrom4([4]byte(laterOut[30:34])); got != token {
			t.Fatalf("fragment rewrite used a different token: first=%s later=%s", token, got)
		}
		if checksum16(laterOut[testEthernetHeaderLength:testEthernetHeaderLength+testIPv4HeaderLength]) != 0 {
			t.Fatal("later fragment has an invalid IPv4 checksum")
		}
	})

	t.Run("fail_closed", func(t *testing.T) {
		unknownLater := testIPv4UDPFragment(
			netip.MustParseAddr("192.0.2.30"), netip.MustParseAddr("203.0.113.30"),
			0, 0, 0x5151, 2, false, []byte("unknown-fragment"),
		)
		action, _ := runSharedNetworkProgram(t, ingress, unknownLater)
		if action != testTCActShot {
			t.Fatalf("unknown later fragment did not fail closed: action=%d", action)
		}

		malformed := testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.40"), netip.MustParseAddr("203.0.113.40"), 55000, 443,
		)[:testEthernetHeaderLength+testIPv4HeaderLength+2]
		action, _ = runSharedNetworkProgram(t, ingress, malformed)
		if action != testTCActShot {
			t.Fatalf("truncated selected packet did not fail closed: action=%d", action)
		}
	})
}

func runSharedNetworkProgram(t *testing.T, program *CiliumEBPF.Program, packet []byte) (uint32, []byte) {
	t.Helper()
	output := make([]byte, len(packet)+256)
	options := &CiliumEBPF.RunOptions{Data: packet, DataOut: output, Repeat: 1}
	action, err := program.Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.DataOut) < len(packet) {
		t.Fatalf("short program output: %d < %d", len(options.DataOut), len(packet))
	}
	return action, options.DataOut[:len(packet)]
}

func testIPv4TCPPacket(source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	packet := testIPv4Packet(source, destination, unix.IPPROTO_TCP, testTCPHeaderLength, 0, 0)
	tcp := packet[testEthernetHeaderLength+testIPv4HeaderLength:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksumIPv4(source, destination, unix.IPPROTO_TCP, tcp))
	return packet
}

func testIPv4UDPFragment(
	source, destination netip.Addr,
	sourcePort, destinationPort, identification, fragmentOffset uint16,
	more bool,
	payload []byte,
) []byte {
	headerLength := 0
	if fragmentOffset == 0 {
		headerLength = testUDPHeaderLength
	}
	fragment := fragmentOffset & 0x1fff
	if more {
		fragment |= 0x2000
	}
	packet := testIPv4Packet(source, destination, unix.IPPROTO_UDP, headerLength+len(payload), identification, fragment)
	transport := packet[testEthernetHeaderLength+testIPv4HeaderLength:]
	if fragmentOffset == 0 {
		binary.BigEndian.PutUint16(transport[0:2], sourcePort)
		binary.BigEndian.PutUint16(transport[2:4], destinationPort)
		binary.BigEndian.PutUint16(transport[4:6], uint16(testUDPHeaderLength+len(payload)))
		copy(transport[testUDPHeaderLength:], payload)
	} else {
		copy(transport, payload)
	}
	return packet
}

func testIPv4Packet(
	source, destination netip.Addr,
	protocol uint8,
	payloadLength int,
	identification, fragment uint16,
) []byte {
	packet := make([]byte, testEthernetHeaderLength+testIPv4HeaderLength+payloadLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[testEthernetHeaderLength:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(testIPv4HeaderLength+payloadLength))
	binary.BigEndian.PutUint16(ip[4:6], identification)
	binary.BigEndian.PutUint16(ip[6:8], fragment)
	ip[8] = 64
	ip[9] = protocol
	source4 := source.As4()
	destination4 := destination.As4()
	copy(ip[12:16], source4[:])
	copy(ip[16:20], destination4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum16(ip[:testIPv4HeaderLength]))
	return packet
}

func assertIPv4TCPRewrite(t *testing.T, packet []byte, prefix netip.Addr, prefixBits int, port uint16) {
	t.Helper()
	destination := netip.AddrFrom4([4]byte(packet[30:34]))
	if !netip.PrefixFrom(prefix, prefixBits).Contains(destination) {
		t.Fatalf("destination was not rewritten into token prefix: %s", destination)
	}
	if got := binary.BigEndian.Uint16(packet[36:38]); got != port {
		t.Fatalf("destination port was not rewritten: %d", got)
	}
	ip := packet[testEthernetHeaderLength : testEthernetHeaderLength+testIPv4HeaderLength]
	if checksum16(ip) != 0 {
		t.Fatal("rewritten packet has an invalid IPv4 checksum")
	}
	tcp := packet[testEthernetHeaderLength+testIPv4HeaderLength:]
	source := netip.AddrFrom4([4]byte(ip[12:16]))
	if transportChecksumIPv4(source, destination, unix.IPPROTO_TCP, tcp) != 0 {
		t.Fatal("rewritten packet has an invalid TCP checksum")
	}
}

func transportChecksumIPv4(source, destination netip.Addr, protocol uint8, payload []byte) uint16 {
	pseudo := make([]byte, 12+len(payload))
	source4 := source.As4()
	destination4 := destination.As4()
	copy(pseudo[0:4], source4[:])
	copy(pseudo[4:8], destination4[:])
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(payload)))
	copy(pseudo[12:], payload)
	return checksum16(pseudo)
}

func checksum16(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
