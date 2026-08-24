package ebpf

import (
	"net/netip"
	"testing"
)

// The list is the Go mirror of sb_ebpf_ipv4_private_address and
// sb_ebpf_ipv6_private_address in native/private_address.h. Spelling the
// expectation out here means an edit to one side without the other fails a
// test instead of silently diverging from the packet program: consumers plan
// routing around this list, so a mismatch would route traffic the program does
// not actually bypass.
func TestPrivateAddressPrefixes(t *testing.T) {
	expected := []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
	prefixes := PrivateAddressPrefixes()
	if len(prefixes) != len(expected) {
		t.Fatalf("expected %d prefixes, got %d: %v", len(expected), len(prefixes), prefixes)
	}
	for index, text := range expected {
		if prefixes[index] != netip.MustParsePrefix(text) {
			t.Fatalf("prefix %d: expected %s, got %s", index, text, prefixes[index])
		}
	}
}

func TestPrivateAddressPrefixesIsCopy(t *testing.T) {
	first := PrivateAddressPrefixes()
	first[0] = netip.MustParsePrefix("203.0.113.0/24")
	if second := PrivateAddressPrefixes(); second[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("caller mutated the shared list: got %s", second[0])
	}
}
