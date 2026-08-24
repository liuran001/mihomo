package resolver

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func restoreFakeIPRanges(t *testing.T) {
	t.Helper()
	ipv4, ipv6 := FakeIPRanges()
	t.Cleanup(func() {
		StoreFakeIPRanges(ipv4, ipv6)
	})
}

func TestStoreFakeIPRangesNotifiesOnChange(t *testing.T) {
	restoreFakeIPRanges(t)
	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})

	type observed struct {
		ipv4 netip.Prefix
		ipv6 netip.Prefix
	}
	var seen []observed
	remove := RegisterFakeIPRangeObserver(func(ipv4 netip.Prefix, ipv6 netip.Prefix) {
		seen = append(seen, observed{ipv4, ipv6})
	})
	defer remove()

	ipv4 := netip.MustParsePrefix("100.64.0.0/10")
	StoreFakeIPRanges(ipv4, netip.Prefix{})
	if len(seen) != 1 || seen[0].ipv4 != ipv4 {
		t.Fatalf("expected one notification carrying the new range, got %v", seen)
	}
	if gotIPv4, gotIPv6 := FakeIPRanges(); gotIPv4 != ipv4 || gotIPv6.IsValid() {
		t.Fatalf("expected %s and no IPv6 range, got %s and %s", ipv4, gotIPv4, gotIPv6)
	}

	// An unchanged publication must not wake observers: updateDNS runs on every
	// config apply, and each notification pushes a map write into the kernel.
	StoreFakeIPRanges(ipv4, netip.Prefix{})
	if len(seen) != 1 {
		t.Fatalf("expected no notification for an unchanged value, got %v", seen)
	}

	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})
	if len(seen) != 2 || seen[1].ipv4.IsValid() {
		t.Fatalf("expected a notification clearing the range, got %v", seen)
	}
}

func TestRegisterFakeIPRangeObserverRemove(t *testing.T) {
	restoreFakeIPRanges(t)
	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})

	calls := 0
	remove := RegisterFakeIPRangeObserver(func(netip.Prefix, netip.Prefix) {
		calls++
	})
	remove()
	// A second removal must stay harmless: the inbound calls its stop path from
	// an idempotent Close.
	remove()

	StoreFakeIPRanges(netip.MustParsePrefix("198.18.0.0/16"), netip.Prefix{})
	if calls != 0 {
		t.Fatalf("expected no calls after removal, got %d", calls)
	}
}

func TestRegisterFakeIPRangeObserverNil(t *testing.T) {
	remove := RegisterFakeIPRangeObserver(nil)
	if remove == nil {
		t.Fatal("expected a usable remove function for a nil observer")
	}
	remove()
}

// The eBPF backends skip a range equal to the one they already hold, so a
// notification that lands out of order is never corrected: the kernel map keeps
// the stale range until the next config change. This pins the ordering by
// holding the first notification open until a second store has overtaken it --
// whoever delivers last has to deliver the value that is actually published.
// A whole store is serialised, so observers see the stores in publication order.
// Two concurrent stores are otherwise free to reach the observers in the
// opposite order, which leaves a consumer that skips a range equal to the one it
// already holds -- what the eBPF backends do -- on the stale range until the
// next config change.
func TestStoreFakeIPRangesNotificationsAreOrdered(t *testing.T) {
	restoreFakeIPRanges(t)
	StoreFakeIPRanges(netip.Prefix{}, netip.Prefix{})

	first := netip.MustParsePrefix("100.64.0.0/10")
	second := netip.MustParsePrefix("198.18.0.0/16")

	var (
		access   sync.Mutex
		observed []netip.Prefix
		inflight atomic.Int32
		overlap  atomic.Bool
	)
	// One token, so only the first notification blocks. sync.Once cannot be used
	// here: a second caller would wait for the first to return, serialising the
	// observer by itself and hiding the very thing under test.
	blockOnce := make(chan struct{}, 1)
	blockOnce <- struct{}{}
	entered := make(chan struct{})
	release := make(chan struct{})

	remove := RegisterFakeIPRangeObserver(func(ipv4 netip.Prefix, _ netip.Prefix) {
		if inflight.Add(1) > 1 {
			overlap.Store(true)
		}
		select {
		case <-blockOnce:
			close(entered)
			<-release
		default:
		}
		access.Lock()
		observed = append(observed, ipv4)
		access.Unlock()
		inflight.Add(-1)
	})
	defer remove()

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		StoreFakeIPRanges(first, netip.Prefix{})
	}()
	waitFor(t, entered, "the first notification to start")

	secondStarted := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		close(secondStarted)
		StoreFakeIPRanges(second, netip.Prefix{})
	}()
	waitFor(t, secondStarted, "the second store to be reached")

	// Without this the test proves nothing: it would assert an order that was
	// never contended. The second store has to still be waiting on the first
	// one's notification, which also means it cannot have published yet.
	select {
	case <-secondDone:
		t.Fatal("expected the second store to wait for the first notification to finish")
	case <-time.After(50 * time.Millisecond):
	}
	if published, _ := FakeIPRanges(); published != first {
		t.Fatalf("expected %s to stay published while the first notification runs, got %s", first, published)
	}

	close(release)
	waitFor(t, firstDone, "the first store to finish")
	waitFor(t, secondDone, "the second store to finish")

	if overlap.Load() {
		t.Fatal("expected two stores never to notify observers at the same time")
	}
	access.Lock()
	defer access.Unlock()
	if len(observed) != 2 || observed[0] != first || observed[1] != second {
		t.Fatalf("expected observers to see %s then %s, got %v", first, second, observed)
	}
	if published, _ := FakeIPRanges(); published != second {
		t.Fatalf("expected %s to be published, got %s", second, published)
	}
}

// waitFor keeps a regression that stops signalling from turning into a package
// timeout panic, which kills every other test in the binary with it.
func waitFor(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}
