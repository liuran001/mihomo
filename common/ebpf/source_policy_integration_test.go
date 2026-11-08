//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

// Source policy semantics shared by both data planes: exclusion lists win, and
// with include lists configured a client is selected when its MAC OR its
// source address is included.
var sourcePolicyIntegrationConfig = PolicyConfig{
	EnableTCP:         true,
	SharedDNSMode:     DNSModeRespectPolicy,
	IncludeSourceMAC:  []MACAddress{{0x02, 0, 0, 0, 0, 1}},
	IncludeSourceCIDR: []netip.Prefix{netip.MustParsePrefix("192.0.2.20/32")},
	ExcludeSourceMAC:  []MACAddress{{0x02, 0, 0, 0, 0, 3}},
	ExcludeSourceCIDR: []netip.Prefix{netip.MustParsePrefix("192.0.2.30/32")},
}

var sourcePolicyIntegrationCases = []struct {
	name     string
	mac      byte
	source   string
	selected bool
}{
	{"included_mac", 1, "192.0.2.10", true},
	{"included_address", 2, "192.0.2.20", true},
	{"included_both", 1, "192.0.2.20", true},
	{"included_neither", 2, "192.0.2.10", false},
	{"excluded_mac_wins", 3, "192.0.2.20", false},
	{"excluded_address_wins", 1, "192.0.2.30", false},
}

func TestTCSourcePolicyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC shared source policy semantics")
	requireTCSocketAssignment(t)
	policy, err := CompilePolicy(sourcePolicyIntegrationConfig)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{ListenerPort: 65531, EnableShared: true, EnableIPv4: true, EnableTCP: true, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	ingress := backend.runtime.programs[tcProgramSharedIngressEthernet]
	for i, tt := range sourcePolicyIntegrationCases {
		t.Run(tt.name, func(t *testing.T) {
			packet := testIPv4TCPPacket(netip.MustParseAddr(tt.source), netip.MustParseAddr("203.0.113.10"), uint16(53100+i), 443)
			packet[11] = tt.mac
			action, _ := runTCProgram(t, ingress, packet)
			want := testTCActUnspec
			if tt.selected {
				want = testTCActShot
			}
			if action != want {
				t.Fatalf("action=%d, want %d", action, want)
			}
		})
	}
}

func TestSharedRewriteSourcePolicyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify packet rewrite shared source policy semantics")
	policy, err := CompilePolicy(sourcePolicyIntegrationConfig)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{ListenerPort: 65531, EnableTCP: true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		UDPTimeout: time.Minute, Policy: policy, MapCapacity: SharedNetworkMapCapacities{Proxy: 64, Bypass: 64}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	for i, tt := range sourcePolicyIntegrationCases {
		t.Run(tt.name, func(t *testing.T) {
			client := netip.AddrPortFrom(netip.MustParseAddr(tt.source), uint16(53200+i))
			packet := sharedRewriteTestPacket(ProtocolTCP, client, netip.MustParseAddrPort("203.0.113.10:443"), nil, false)
			packet[11] = tt.mac
			action, out := runTCProgram(t, backend.IngressProgram(), packet)
			if tt.selected {
				if action != sharedRewriteTestTCActOK || bytes.Equal(out, packet) {
					t.Fatalf("selected client not rewritten: action=%d", action)
				}
			} else if action != testTCActUnspec || !bytes.Equal(out, packet) {
				t.Fatalf("unselected client intercepted: action=%d changed=%v", action, !bytes.Equal(out, packet))
			}
		})
	}
}
