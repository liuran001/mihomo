//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"

	list "github.com/metacubex/sing/common/x/list"

	tun "github.com/metacubex/sing-tun"
)

// recordingNetworkMonitor stands in for the netlink subscription so the borrow
// path can be exercised without a kernel that grants one.
type recordingNetworkMonitor struct {
	callbacks    list.List[tun.NetworkUpdateCallback]
	registered   int
	unregistered []*list.Element[tun.NetworkUpdateCallback]
	closed       int
}

func (m *recordingNetworkMonitor) Start() error { return nil }

func (m *recordingNetworkMonitor) Close() error {
	m.closed++
	return nil
}

func (m *recordingNetworkMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	m.registered++
	return m.callbacks.PushBack(callback)
}

func (m *recordingNetworkMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.unregistered = append(m.unregistered, element)
	m.callbacks.Remove(element)
}

var _ tun.NetworkUpdateMonitor = (*recordingNetworkMonitor)(nil)

// startLocalNetworkMonitor borrows the shared TC manager's netlink subscription
// instead of opening a second one. Every step of that lookup has to report "no
// monitor" rather than panic, because each one is a real state the inbound
// starts in: local mode has no shared network at all, and the shared network
// reaches Start with no TC manager and then with a manager whose monitor the
// kernel refused to create.
func TestSharedNetworkMonitorInstanceReportsAbsence(t *testing.T) {
	var absent *sharedNetwork
	if absent.networkMonitorInstance() != nil {
		t.Fatal("expected a nil shared network to report no monitor")
	}

	shared := &sharedNetwork{}
	if shared.networkMonitorInstance() != nil {
		t.Fatal("expected a shared network without a TC manager to report no monitor")
	}

	shared.tcManager = &sharedTCManager{}
	if shared.networkMonitorInstance() != nil {
		t.Fatal("expected a TC manager whose monitor was never created to report no monitor")
	}
}

// In hybrid mode the shared TC manager already holds a subscription, so the
// inbound hangs its callback off that one rather than opening a second netlink
// socket for the lifetime of the process. What it borrowed it must not close.
func TestStartLocalNetworkMonitorBorrowsTheSharedSubscription(t *testing.T) {
	monitor := &recordingNetworkMonitor{}
	inbound := &Inbound{
		sharedNetwork: &sharedNetwork{tcManager: &sharedTCManager{networkMonitor: monitor}},
	}

	inbound.startLocalNetworkMonitor()

	local := inbound.localNetwork
	if local == nil {
		t.Fatal("expected the inbound to record a monitor")
	}
	if local.monitor != monitor {
		t.Fatal("expected the shared subscription to be reused instead of a second one")
	}
	if local.owned {
		t.Fatal("expected a borrowed subscription not to be owned")
	}
	if monitor.registered != 1 {
		t.Fatalf("expected exactly one callback registration, got %d", monitor.registered)
	}
	registered := local.callback
	if registered == nil {
		t.Fatal("expected the registration to be recorded so it can be undone")
	}

	inbound.stopLocalNetworkMonitor()

	if monitor.closed != 0 {
		t.Fatalf("expected a borrowed subscription never to be closed, closed %d time(s)", monitor.closed)
	}
	if len(monitor.unregistered) != 1 || monitor.unregistered[0] != registered {
		t.Fatalf("expected the inbound to detach exactly its own callback, detached %d", len(monitor.unregistered))
	}
	if inbound.localNetwork != nil {
		t.Fatal("expected the monitor to be cleared")
	}
}

// The subscription an inbound opened for itself is its to close: nothing else
// holds a reference, so leaving it open leaks a netlink socket and its
// goroutines for the lifetime of the process.
func TestStopLocalNetworkMonitorClosesWhatItOwns(t *testing.T) {
	monitor := &recordingNetworkMonitor{}
	registered := monitor.RegisterCallback(func() {})
	inbound := &Inbound{
		localNetwork: &localNetworkMonitor{monitor: monitor, callback: registered, owned: true},
	}

	inbound.stopLocalNetworkMonitor()

	if monitor.closed != 1 {
		t.Fatalf("expected an owned subscription to be closed once, closed %d time(s)", monitor.closed)
	}
	if len(monitor.unregistered) != 1 || monitor.unregistered[0] != registered {
		t.Fatalf("expected the callback to be detached first, detached %d", len(monitor.unregistered))
	}
	if inbound.localNetwork != nil {
		t.Fatal("expected the monitor to be cleared")
	}
}

// Stopping an inbound that never started one must stay a no-op: the monitor is
// best effort, so a kernel that refused the subscription leaves nothing behind.
func TestStopLocalNetworkMonitorWithoutOne(t *testing.T) {
	inbound := &Inbound{}
	inbound.stopLocalNetworkMonitor()
	if inbound.localNetwork != nil {
		t.Fatal("expected stopping an unstarted monitor to stay a no-op")
	}
}
