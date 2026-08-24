//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"
	"unsafe"
)

func TestSpliceABI(t *testing.T) {
	if size := unsafe.Sizeof(spliceKey{}); size != 40 {
		t.Fatalf("unexpected TCP splice key size: %d", size)
	}
}

func TestMakeSpliceKey(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	key, err := makeSpliceKey(client)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != 2 || key.Protocol != 6 || key.LocalPort == 0 || key.RemotePort == 0 {
		t.Fatalf("unexpected TCP splice key: %+v", key)
	}
}

func TestSpliceFallbackReasons(t *testing.T) {
	backend := &SpliceBackend{pairs: make(map[*SplicePair]struct{})}
	backend.RecordFallback(SpliceFallbackNotDirect)
	backend.RecordFallback(SpliceFallbackNotDirect)
	backend.RecordFallback(SpliceFallbackActivate)
	backend.RecordFallback(SpliceFallbackPowerReportActive)
	statistics := backend.Statistics()
	if statistics.Fallbacks != 4 || statistics.FallbackReasons["not_direct"] != 2 ||
		statistics.FallbackReasons["activate"] != 1 || statistics.FallbackReasons["power_report_active"] != 1 {
		t.Fatalf("unexpected TCP splice fallback statistics: %+v", statistics)
	}
}
