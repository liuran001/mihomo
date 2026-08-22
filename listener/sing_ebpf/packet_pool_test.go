//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"

	"github.com/metacubex/mihomo/common/pool"
)

// The pooled read path is only safe if a buffer goes back exactly once. Drop is
// reachable more than once in principle -- the tunnel drops a packet on several
// paths -- so it has to be harmless the second time, and it must not hand back
// a buffer the caller can still read through Data().
func TestUDPPacketDropReturnsBufferOnce(t *testing.T) {
	t.Parallel()
	packet := &udpPacket{data: pool.Get(1500)}
	if len(packet.Data()) != 1500 {
		t.Fatalf("Data() length is %d, want 1500", len(packet.Data()))
	}
	packet.Drop()
	if packet.Data() != nil {
		t.Fatal("Drop left the payload reachable; a second Drop would double-return it")
	}
	packet.Drop() // must not panic and must not return a second buffer
}

func TestSharedPacketDropReturnsBufferOnce(t *testing.T) {
	t.Parallel()
	packet := &sharedPacket{data: pool.Get(1500)}
	if len(packet.Data()) != 1500 {
		t.Fatalf("Data() length is %d, want 1500", len(packet.Data()))
	}
	packet.Drop()
	if packet.Data() != nil {
		t.Fatal("Drop left the payload reachable; a second Drop would double-return it")
	}
	packet.Drop()
}

// pool.Put rejects a buffer whose capacity is not a power of two. Every size the
// UDP read loop can produce comes from pool.Get, so this pins that the whole
// range round-trips rather than silently failing and losing the buffer.
func TestPooledPayloadSizesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 64, 512, 1500, 4096, 9000, 65535, 65536} {
		buffer := pool.Get(size)
		if len(buffer) != size {
			t.Fatalf("pool.Get(%d) returned length %d", size, len(buffer))
		}
		if err := pool.Put(buffer); err != nil {
			t.Fatalf("pool.Put of a %d-byte payload failed: %v", size, err)
		}
	}
}

// A zero-length read is skipped by the loop, but Drop still has to tolerate the
// nil that pool.Get(0) hands back.
func TestDropToleratesEmptyPayload(t *testing.T) {
	t.Parallel()
	(&udpPacket{data: pool.Get(0)}).Drop()
	(&sharedPacket{data: nil}).Drop()
}
