package statistic

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/health"
	C "github.com/metacubex/mihomo/constant"
)

type trackerTestNetConn struct{}

func (trackerTestNetConn) Read([]byte) (int, error)         { return 0, nil }
func (trackerTestNetConn) Write(b []byte) (int, error)      { return len(b), nil }
func (trackerTestNetConn) Close() error                     { return nil }
func (trackerTestNetConn) LocalAddr() net.Addr              { return nil }
func (trackerTestNetConn) RemoteAddr() net.Addr             { return nil }
func (trackerTestNetConn) SetDeadline(time.Time) error      { return nil }
func (trackerTestNetConn) SetReadDeadline(time.Time) error  { return nil }
func (trackerTestNetConn) SetWriteDeadline(time.Time) error { return nil }

type trackerTestConn struct {
	N.ExtendedConn
	chain      C.Chain
	closeErr   error
	closeCalls atomic.Int32
}

func newTrackerTestConn(name string, closeErr error) *trackerTestConn {
	return &trackerTestConn{
		ExtendedConn: N.NewExtendedConn(trackerTestNetConn{}),
		chain:        C.Chain{name},
		closeErr:     closeErr,
	}
}

func (c *trackerTestConn) Close() error {
	c.closeCalls.Add(1)
	return c.closeErr
}

func (c *trackerTestConn) Chains() C.Chain               { return c.chain }
func (c *trackerTestConn) ProviderChains() C.Chain       { return nil }
func (c *trackerTestConn) AppendToChains(C.ProxyAdapter) {}
func (c *trackerTestConn) RemoteDestination() string     { return "example.com:443" }

func TestTCPTrackerStallIgnoresInitialUpload(t *testing.T) {
	name := t.Name()
	manager := &Manager{}
	conn := newTrackerTestConn(name, nil)
	tracker := NewTCPTracker(conn, manager, &C.Metadata{}, nil, 128, 0, false)

	if err := tracker.Close(); err != nil {
		t.Fatalf("close tracker: %v", err)
	}
	if got := health.Incidents(name); got != 0 {
		t.Fatalf("initial peek upload must not count as a stall, got %d incidents", got)
	}
}

func TestTCPTrackerCloseReportsStallOnce(t *testing.T) {
	name := t.Name()
	manager := &Manager{}
	closeErr := errors.New("close failed")
	conn := newTrackerTestConn(name, closeErr)
	tracker := NewTCPTracker(conn, manager, &C.Metadata{}, nil, 128, 0, false)

	if _, err := tracker.Write([]byte("payload after peek")); err != nil {
		t.Fatalf("write tracker: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := tracker.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("close %d returned %v, want %v", i+1, err, closeErr)
		}
	}

	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying connection closed %d times, want 1", got)
	}
	if got := health.Incidents(name); got != 1 {
		t.Fatalf("stall recorded %d times, want 1", got)
	}
	if got := manager.Get(tracker.ID()); got != nil {
		t.Fatal("closed tracker remained registered with manager")
	}
}
