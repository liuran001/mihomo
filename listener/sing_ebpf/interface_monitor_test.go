//go:build with_ebpf && (linux || android)

// Regression cases adapted from CHIZI-0618/sing-box at 4af7ae48.
package sing_ebpf

import (
	"errors"
	commonEBPF "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/power"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/x/list"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
	"net"
	"slices"
	"testing"
)

func TestDesiredTCAttachmentState(t *testing.T) {
	links := map[string]int{"wlan2": 12, "rndis0": 27}
	interfaces, err := desiredTCAttachmentState(
		"wlan2",
		[]string{"wlan2", "missing0", "rndis0"},
		func(name string) (netlink.Link, error) {
			index, loaded := links[name]
			if !loaded {
				return nil, unix.ENODEV
			}
			return testEthernetLink(name, index), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 2 ||
		interfaces["wlan2"].role != (tcInterfaceRole{local: true, shared: true}) ||
		interfaces["rndis0"].role != (tcInterfaceRole{shared: true}) {
		t.Fatalf("unexpected desired interfaces: %+v", interfaces)
	}
	if interfaces["wlan2"].framing != commonEBPF.TCLinkFramingEthernet {
		t.Fatalf("unexpected wlan2 framing: %v", interfaces["wlan2"].framing)
	}

	expectedErr := errors.New("lookup failed")
	_, err = desiredTCAttachmentState("", []string{"wlan2"}, func(string) (netlink.Link, error) {
		return nil, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("unexpected lookup error: %v", err)
	}
}

func TestTCAttachmentTopologyChanged(t *testing.T) {
	attachment := func(name string, index int, role tcInterfaceRole) *tcInterfaceAttachment {
		return &tcInterfaceAttachment{
			interfaceName:  name,
			interfaceIndex: index,
			framing:        commonEBPF.TCLinkFramingEthernet,
			role:           role,
		}
	}
	state := func(index int, role tcInterfaceRole) tcAttachmentState {
		return tcAttachmentState{index: index, framing: commonEBPF.TCLinkFramingEthernet, role: role}
	}
	testCases := []struct {
		name        string
		attachments []*tcInterfaceAttachment
		desired     map[string]tcAttachmentState
		changed     bool
	}{
		{"empty", nil, map[string]tcAttachmentState{}, false},
		{"appeared", nil, map[string]tcAttachmentState{"wlan2": state(12, tcInterfaceRole{shared: true})}, true},
		{
			"unchanged",
			[]*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})},
			map[string]tcAttachmentState{"wlan2": state(12, tcInterfaceRole{shared: true})},
			false,
		},
		{
			"deleted",
			[]*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})},
			map[string]tcAttachmentState{},
			true,
		},
		{
			"recreated",
			[]*tcInterfaceAttachment{attachment("wlan2", 12, tcInterfaceRole{shared: true})},
			map[string]tcAttachmentState{"wlan2": state(31, tcInterfaceRole{shared: true})},
			true,
		},
		{
			"role changed",
			[]*tcInterfaceAttachment{attachment("wlan0", 8, tcInterfaceRole{local: true, shared: true})},
			map[string]tcAttachmentState{"wlan0": state(8, tcInterfaceRole{local: true})},
			true,
		},
		{
			"framing changed",
			[]*tcInterfaceAttachment{attachment("rmnet_data2", 21, tcInterfaceRole{local: true})},
			map[string]tcAttachmentState{"rmnet_data2": {
				index:   21,
				framing: commonEBPF.TCLinkFramingRawIP,
				role:    tcInterfaceRole{local: true},
			}},
			true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if changed := tcAttachmentTopologyChanged(testCase.attachments, testCase.desired); changed != testCase.changed {
				t.Fatalf("unexpected topology result: %v", changed)
			}
		})
	}
}

func TestActiveSharedInterfaces(t *testing.T) {
	configured := []string{"wlan0", "rndis0"}
	if active := activeSharedInterfaces(configured, "wlan0", false); !slices.Equal(active, []string{"rndis0"}) {
		t.Fatalf("default upstream was not excluded: %v", active)
	}
	if active := activeSharedInterfaces(configured, "rmnet_data2", false); !slices.Equal(active, configured) {
		t.Fatalf("downstream interfaces changed unexpectedly: %v", active)
	}
	// Single-interface bypass router: the only NIC is both downstream and the default upstream, so allow-default-upstream must keep it.
	if active := activeSharedInterfaces(configured, "wlan0", true); !slices.Equal(active, configured) {
		t.Fatalf("default upstream was excluded despite allow-default-upstream: %v", active)
	}
	if active := activeSharedInterfaces(configured, "", true); !slices.Equal(active, configured) {
		t.Fatalf("interfaces changed unexpectedly with allow-default-upstream: %v", active)
	}
	if !slices.Equal(configured, []string{"wlan0", "rndis0"}) {
		t.Fatalf("configured interfaces were modified: %v", configured)
	}
}

func TestTCInterfaceMonitorLifecycle(t *testing.T) {
	network := &testNetworkUpdateMonitor{}
	defaults := &testDefaultInterfaceMonitor{current: &control.Interface{Name: "wlan0", Index: 8}}
	i := &Inbound{}
	if err := i.startTCInterfaceMonitors(network, defaults); err != nil {
		t.Fatal(err)
	}
	workerDone := i.interfaceMonitor.done
	defer i.stopTCInterfaceMonitor()
	if network.callbackCount() != 1 || defaults.callbackCount() != 1 {
		t.Fatal("missing callbacks")
	}
	if i.monitoredDefaultInterfaceName() != "wlan0" {
		t.Fatal("missing initial interface")
	}
	defaults.emit(nil)
	if paused, _ := power.BackgroundState(); !paused {
		t.Fatal("offline monitor did not pause background tasks")
	}
	defaults.emit(&control.Interface{Name: "rmnet_data1", Index: 19})
	if paused, _ := power.BackgroundState(); paused {
		t.Fatal("network recovery did not resume background tasks")
	}
	if err := i.stopTCInterfaceMonitor(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-workerDone:
	default:
		t.Fatal("monitor returned before its update worker exited")
	}
	if network.callbackCount() != 0 || defaults.callbackCount() != 0 {
		t.Fatal("callbacks retained after close")
	}
	if i.interfaceMonitor.backgroundNetwork != nil {
		t.Fatal("network source retained after close")
	}
	i.defaultInterfaceUpdated(nil, 0)
	if paused, _ := power.BackgroundState(); paused {
		t.Fatal("late callback paused background work")
	}
}

func TestTCInterfaceMonitorStartFailureReleasesOwnership(t *testing.T) {
	for _, failDefault := range []bool{false, true} {
		network := &testNetworkUpdateMonitor{}
		defaults := &testDefaultInterfaceMonitor{}
		failure := errors.New("monitor startup failed")
		if failDefault {
			defaults.startErr = failure
		} else {
			network.startErr = failure
		}
		i := &Inbound{}
		if err := i.startTCInterfaceMonitors(network, defaults); !errors.Is(err, failure) {
			t.Fatalf("unexpected startup result: %v", err)
		}
		if network.callbackCount() != 0 || defaults.callbackCount() != 0 || network.closes != 1 || defaults.closes != 1 {
			t.Fatal("failed startup retained callbacks or monitor ownership")
		}
		if i.interfaceMonitor.backgroundNetwork != nil || i.interfaceMonitor.done != nil {
			t.Fatal("failed startup retained background resources")
		}
		if paused, _ := power.BackgroundState(); paused {
			t.Fatal("failed startup left background work paused")
		}
	}
}
func TestTCInterfaceNotificationsCoalesce(t *testing.T) {
	updates := make(chan struct{}, 1)
	i := &Inbound{interfaceMonitor: tcInterfaceMonitor{network: &testNetworkUpdateMonitor{}, updates: updates}}
	for n := 0; n < 100; n++ {
		i.notifyTCInterfaceUpdate()
	}
	if len(updates) != 1 {
		t.Fatalf("pending updates=%d", len(updates))
	}
}
func testEthernetLink(name string, index int) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         name,
		Index:        index,
		EncapType:    "ether",
		HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5},
	}}
}

type testNetworkUpdateMonitor struct {
	callbacks list.List[tun.NetworkUpdateCallback]
	startErr  error
	closes    int
}

func (m *testNetworkUpdateMonitor) Start() error { return m.startErr }

func (m *testNetworkUpdateMonitor) Close() error { m.closes++; return nil }

func (m *testNetworkUpdateMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *testNetworkUpdateMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *testNetworkUpdateMonitor) callbackCount() int {
	return len(m.callbacks.Array())
}

type testDefaultInterfaceMonitor struct {
	current   *control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
	startErr  error
	closes    int
}

func (m *testDefaultInterfaceMonitor) Start() error { return m.startErr }

func (m *testDefaultInterfaceMonitor) Close() error { m.closes++; return nil }

func (m *testDefaultInterfaceMonitor) DefaultInterface() *control.Interface { return m.current }

func (m *testDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (m *testDefaultInterfaceMonitor) AndroidVPNEnabled() bool { return false }

func (m *testDefaultInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *testDefaultInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *testDefaultInterfaceMonitor) RegisterMyInterface(string) {}

func (m *testDefaultInterfaceMonitor) MyInterfaces() []string { return nil }

func (m *testDefaultInterfaceMonitor) callbackCount() int {
	return len(m.callbacks.Array())
}

func (m *testDefaultInterfaceMonitor) emit(networkInterface *control.Interface) {
	m.current = networkInterface
	for _, callback := range m.callbacks.Array() {
		callback(networkInterface, 0)
	}
}
