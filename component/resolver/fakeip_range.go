package resolver

import (
	"net/netip"
	"sync"
)

// FakeIPRangeObserver is notified whenever the published ranges change. It is
// invoked without the registry lock held, so an observer is free to read the
// ranges back or to touch the registry again. It must not call
// StoreFakeIPRanges itself: notifications are serialised, so that would
// deadlock.
type FakeIPRangeObserver = func(ipv4 netip.Prefix, ipv6 netip.Prefix)

// The fake-ip ranges are published here for consumers that need the prefixes
// themselves rather than a membership test on an address the pool has already
// handed out. Enhancer only answers "is this a fake ip", which is of no use to
// a component that has to compile the range into a policy before any traffic
// exists: the eBPF inbound pushes the prefix and mask into a kernel map so its
// packet program can force interception for fake-ip destinations even when the
// configured range sits inside a range the same program would otherwise bypass
// (100.64.0.0/10, say).
var (
	fakeIPRangeAccess    sync.Mutex
	fakeIPRangeIPv4      netip.Prefix
	fakeIPRangeIPv6      netip.Prefix
	fakeIPRangeObservers map[int64]FakeIPRangeObserver
	fakeIPRangeNextID    int64
	// fakeIPRangeNotify serialises a whole store, so that observers are notified
	// in publication order. It is always taken before fakeIPRangeAccess and
	// never while holding it.
	fakeIPRangeNotify sync.Mutex
)

// StoreFakeIPRanges publishes the active fake-ip ranges and notifies observers
// when they changed. A family without an active pool must be published as a
// zero prefix so consumers stop forcing interception for it.
//
// A whole store is serialised, so observers are notified in publication order.
// Two concurrent stores are otherwise free to reach the observers in the
// opposite order, and a consumer that skips a range equal to the one it already
// holds -- which is what the eBPF backends do -- would then keep the stale range
// until the next config change. The only caller today is already serialised by
// the executor; this keeps the guarantee in the registry rather than resting on
// that.
func StoreFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) {
	fakeIPRangeNotify.Lock()
	defer fakeIPRangeNotify.Unlock()

	fakeIPRangeAccess.Lock()
	if ipv4 == fakeIPRangeIPv4 && ipv6 == fakeIPRangeIPv6 {
		fakeIPRangeAccess.Unlock()
		return
	}
	fakeIPRangeIPv4 = ipv4
	fakeIPRangeIPv6 = ipv6
	observers := make([]FakeIPRangeObserver, 0, len(fakeIPRangeObservers))
	for _, observer := range fakeIPRangeObservers {
		observers = append(observers, observer)
	}
	fakeIPRangeAccess.Unlock()

	for _, observer := range observers {
		observer(ipv4, ipv6)
	}
}

// FakeIPRanges returns the active fake-ip ranges. Both are zero prefixes when
// fake-ip is not in use.
func FakeIPRanges() (netip.Prefix, netip.Prefix) {
	fakeIPRangeAccess.Lock()
	defer fakeIPRangeAccess.Unlock()
	return fakeIPRangeIPv4, fakeIPRangeIPv6
}

// RegisterFakeIPRangeObserver installs an observer and returns the function
// that removes it again. The observer is not called for the current value;
// read it with FakeIPRanges after registering.
func RegisterFakeIPRangeObserver(observer FakeIPRangeObserver) (remove func()) {
	if observer == nil {
		return func() {}
	}
	fakeIPRangeAccess.Lock()
	if fakeIPRangeObservers == nil {
		fakeIPRangeObservers = make(map[int64]FakeIPRangeObserver)
	}
	fakeIPRangeNextID++
	id := fakeIPRangeNextID
	fakeIPRangeObservers[id] = observer
	fakeIPRangeAccess.Unlock()
	return func() {
		fakeIPRangeAccess.Lock()
		delete(fakeIPRangeObservers, id)
		fakeIPRangeAccess.Unlock()
	}
}
