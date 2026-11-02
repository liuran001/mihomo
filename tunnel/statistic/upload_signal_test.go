package statistic

import (
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

func signaled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestUploadSignalFiresOnNextUploadOnly(t *testing.T) {
	m := &Manager{}
	var stamp TrackerInfo

	// Nobody armed it: uploads take the lock-free path and leave nothing behind.
	m.noteUpload(&stamp.LastUpload, 10)
	ch := m.UploadSignal()
	if signaled(ch) {
		t.Fatal("signal fired before any upload after arming")
	}
	if again := m.UploadSignal(); again != ch {
		t.Fatal("arming twice returned a different channel")
	}
	m.noteUpload(&stamp.LastUpload, 0)
	if signaled(ch) {
		t.Fatal("a zero-byte write fired the signal")
	}
	m.noteUpload(&stamp.LastUpload, 1)
	if !signaled(ch) {
		t.Fatal("an upload did not fire the armed signal")
	}
	if next := m.UploadSignal(); signaled(next) {
		t.Fatal("re-armed signal is already closed")
	}
}

func TestUploadSignalFiresForTrackerWrites(t *testing.T) {
	newConn := func() *trackerTestConn {
		return &trackerTestConn{ExtendedConn: N.NewExtendedConn(trackerTestNetConn{}), chain: C.Chain{uniqueTrackerTestName(t)}}
	}
	m := &Manager{}

	ch := m.UploadSignal()
	tracker := NewTCPTracker(newConn(), m, &C.Metadata{}, nil, 0, 0, false)
	defer tracker.Close()
	if signaled(ch) {
		t.Fatal("joining a tracker with nothing sent fired the signal")
	}
	if _, err := tracker.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if !signaled(ch) {
		t.Fatal("a tracked write did not fire the signal")
	}

	// Bytes sent during the dial count as an upload once the tracker joins.
	ch = m.UploadSignal()
	peeked := NewTCPTracker(newConn(), m, &C.Metadata{}, nil, 128, 0, false)
	defer m.Leave(peeked)
	if !signaled(ch) {
		t.Fatal("a tracker joining with initial upload did not fire the signal")
	}
	if !peeked.Info().ReplyPending() {
		t.Fatal("initial upload with no reply is not pending")
	}
}
