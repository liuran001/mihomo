package statistic

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/health"
	C "github.com/metacubex/mihomo/constant"
)

var trackerTestSequence atomic.Uint64

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
	chain         C.Chain
	providerChain C.Chain
	closeErr      error
	closeCalls    atomic.Int32
}

func newTrackerTestConn(name string, closeErr error) *trackerTestConn {
	return &trackerTestConn{
		ExtendedConn: N.NewExtendedConn(trackerTestNetConn{}),
		chain:        C.Chain{name},
		closeErr:     closeErr,
	}
}

func uniqueTrackerTestName(t *testing.T) string {
	return fmt.Sprintf("%s-%d", t.Name(), trackerTestSequence.Add(1))
}

func (c *trackerTestConn) Close() error {
	c.closeCalls.Add(1)
	return c.closeErr
}

func (c *trackerTestConn) Chains() C.Chain               { return c.chain }
func (c *trackerTestConn) ProviderChains() C.Chain       { return c.providerChain }
func (c *trackerTestConn) AppendToChains(C.ProxyAdapter) {}
func (c *trackerTestConn) RemoteDestination() string     { return "example.com:443" }

func TestTCPTrackerStallIgnoresInitialUpload(t *testing.T) {
	name := uniqueTrackerTestName(t)
	manager := &Manager{}
	conn := newTrackerTestConn(name, nil)
	tracker := NewTCPTracker(conn, manager, &C.Metadata{}, nil, 128, 0, false)

	if err := tracker.Close(); err != nil {
		t.Fatalf("close tracker: %v", err)
	}
	if got := health.Incidents(health.ProxyKey(name, "")); got != 0 {
		t.Fatalf("initial peek upload must not count as a stall, got %d incidents", got)
	}
}

func TestTCPTrackerCloseReportsStallOnce(t *testing.T) {
	name := uniqueTrackerTestName(t)
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
	if got := health.Incidents(health.ProxyKey(name, "")); got != 1 {
		t.Fatalf("stall recorded %d times, want 1", got)
	}
	if got := manager.Get(tracker.ID()); got != nil {
		t.Fatal("closed tracker remained registered with manager")
	}
}

// 一条连接的 Chain 是从叶子节点向外展开的：Chain[0] 是真正承载流量的节点，
// 后面依次是包住它的各层 group。url-test 查惩罚时用的是它自己直接成员的名字，
// 对嵌套 group 来说那是子 group 而不是叶子节点 —— 只把事故记在 Chain[0] 上，
// 外层 group 就永远看不见它下面的节点在黑洞流量。
func TestTCPTrackerStallReachesEveryChainHop(t *testing.T) {
	leaf := uniqueTrackerTestName(t)
	inner := leaf + "-inner-group"
	outer := leaf + "-outer-group"

	manager := &Manager{}
	conn := newTrackerTestConn(leaf, nil)
	conn.chain = C.Chain{leaf, inner, outer}
	conn.providerChain = C.Chain{"leaf-provider", "", ""}

	tracker := NewTCPTracker(conn, manager, &C.Metadata{}, nil, 128, 0, false)
	if _, err := tracker.Write([]byte("payload after peek")); err != nil {
		t.Fatalf("write tracker: %v", err)
	}
	if err := tracker.Close(); err != nil {
		t.Fatalf("close tracker: %v", err)
	}

	for index, name := range conn.chain {
		provider := conn.providerChain[index]
		if got := health.Incidents(health.ProxyKey(name, provider)); got != 1 {
			t.Errorf("链路第 %d 跳 %q 记录了 %d 次事故，期望 1 次", index, name, got)
		}
	}
	// 叶子节点的 provider 必须参与构键，否则同名不同机场的节点会互相污染。
	if got := health.Incidents(health.ProxyKey(leaf, "")); got != 0 {
		t.Errorf("叶子节点的事故被记到了空 provider 上：%d", got)
	}
}
