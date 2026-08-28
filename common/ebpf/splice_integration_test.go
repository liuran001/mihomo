//go:build with_ebpf && ebpf_integration && (linux || android)

package ebpf

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestSpliceDataPathIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_INTEGRATION=1 to run privileged eBPF integration tests")
	}
	backend, err := PrepareSplice()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err = backend.Attach(); err != nil {
		t.Fatal(err)
	}

	leftListener := listenSpliceTCP(t)
	defer leftListener.Close()
	external := dialSpliceTCP(t, leftListener.Addr())
	defer external.Close()
	left, err := leftListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()

	rightListener := listenSpliceTCP(t)
	defer rightListener.Close()
	right := dialSpliceTCP(t, rightListener.Addr())
	defer right.Close()
	server, err := rightListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	pair, err := backend.BeginPair(left, right, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Release()
	if err = pair.Activate(); err != nil {
		t.Fatal(err)
	}
	assertSplicePayload(t, external, server, []byte("upload"))
	assertSplicePayload(t, server, external, []byte("download"))
}

func listenSpliceTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func dialSpliceTCP(t *testing.T, destination net.Addr) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTCP("tcp4", nil, destination.(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func assertSplicePayload(t *testing.T, source, destination *net.TCPConn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	_ = source.SetWriteDeadline(deadline)
	_ = destination.SetReadDeadline(deadline)
	if _, err := source.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(destination, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("unexpected spliced payload: %q", received)
	}
}
