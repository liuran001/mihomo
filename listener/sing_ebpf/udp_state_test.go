//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"
	"time"
)

func TestUDPClientTableCachedPacketStateTouchesActivity(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.10:443")
	token := netip.MustParseAddr("127.128.0.10")
	table.setBinding(client, destination, token, false)

	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	old := time.Now().Add(-time.Hour)
	state.access.Lock()
	state.lastActive = old
	state.access.Unlock()

	_, ready, loaded := table.cachedPacketState(client, token)
	if !loaded || !ready {
		t.Fatalf("cached binding loaded=%v ready=%v", loaded, ready)
	}
	state.access.RLock()
	lastActive := state.lastActive
	state.access.RUnlock()
	if !lastActive.After(old) {
		t.Fatalf("lastActive was not refreshed: %v <= %v", lastActive, old)
	}

	table.sweep(time.Now(), time.Minute, func([]udpRedirectRelease) {
		t.Fatal("active UDP client was swept")
	})
	if _, loaded = table.load(client); !loaded {
		t.Fatal("active UDP client was removed by sweep")
	}
}
