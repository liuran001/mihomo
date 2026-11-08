package statistic

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func sourceTestMetadata(source string) *C.Metadata {
	return &C.Metadata{SrcIP: netip.MustParseAddr(source)}
}

func TestSourceTrafficCountsOnlyManagerTrackers(t *testing.T) {
	m := &Manager{}
	first := m.sourceCounterFor(sourceTestMetadata("192.168.43.20"))
	mapped := m.sourceCounterFor(sourceTestMetadata("::ffff:192.168.43.20"))
	if first == nil || first != mapped {
		t.Fatal("IPv4-mapped source did not share the IPv4 counter")
	}
	first.addUpload(10)
	first.addDownload(100)
	mapped.addDownload(2)
	m.sourceCounterFor(sourceTestMetadata("fd00::5")).addUpload(3)
	if m.sourceCounterFor(&C.Metadata{}) != nil {
		t.Fatal("unknown source got a counter")
	}
	var nilCounter *sourceCounter
	nilCounter.addUpload(1) // trackers without a counter must not panic

	got := m.SourceTraffic()
	want := []SourceTraffic{
		{Source: netip.MustParseAddr("192.168.43.20"), Upload: 10, Download: 102},
		{Source: netip.MustParseAddr("fd00::5"), Upload: 3},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	m.ResetStatistic()
	if got = m.SourceTraffic(); len(got) != 0 {
		t.Fatalf("reset kept %+v", got)
	}
	first.addDownload(5)
	if got = m.SourceTraffic(); len(got) != 1 || got[0].Download != 5 {
		t.Fatalf("counter held by a live connection stopped counting after reset: %+v", got)
	}
}

func TestSourceTrafficTableIsBounded(t *testing.T) {
	m := &Manager{}
	m.sourceCount.Store(maxTrackedSources)
	if m.sourceCounterFor(sourceTestMetadata("10.0.0.1")) != nil {
		t.Fatal("full table still added a source")
	}
}

// ageSource pretends the counter's last connection closed long ago and lets
// the next sweep run right away.
func ageSource(m *Manager, counter *sourceCounter) {
	counter.idleSince.Store(time.Now().Add(-sourceIdleTTL - time.Minute).UnixNano())
	m.sourceSweep.Store(0)
}

func TestSourceTrafficDropsIdleSources(t *testing.T) {
	m := &Manager{}
	gone := m.sourceCounterFor(sourceTestMetadata("fd00::1"))
	gone.addDownload(10)
	live := m.sourceCounterFor(sourceTestMetadata("fd00::2"))
	live.addDownload(20)
	recent := m.sourceCounterFor(sourceTestMetadata("fd00::3"))
	recent.addDownload(30)

	gone.release()
	recent.release()
	ageSource(m, gone)
	ageSource(m, live) // still has a live connection: kept however old
	m.sourceSweep.Store(0)

	got := m.SourceTraffic()
	if len(got) != 2 || got[0].Source != netip.MustParseAddr("fd00::2") || got[1].Source != netip.MustParseAddr("fd00::3") {
		t.Fatalf("got %+v, want only the live and the recently closed source", got)
	}
	if n := m.sourceCount.Load(); n != 2 {
		t.Fatalf("source count %d after dropping one of three", n)
	}

	// A device that comes back starts a fresh counter.
	again := m.sourceCounterFor(sourceTestMetadata("fd00::1"))
	if again == gone || again.download.Load() != 0 {
		t.Fatal("dropped counter was handed out again")
	}
	again.addDownload(1)

	// Sweeps are rate-limited: an aged source waits for the next interval.
	recent.idleSince.Store(time.Now().Add(-sourceIdleTTL - time.Minute).UnixNano())
	if got = m.SourceTraffic(); len(got) != 3 {
		t.Fatalf("sweep ran again within the interval: %+v", got)
	}
}

func TestSourceTrafficFullTableMakesRoom(t *testing.T) {
	m := &Manager{}
	old := m.sourceCounterFor(sourceTestMetadata("10.0.0.1"))
	old.release()
	ageSource(m, old)
	m.sourceCount.Store(maxTrackedSources) // pretend the rest of the table is in use
	if m.sourceCounterFor(sourceTestMetadata("10.0.0.2")) == nil {
		t.Fatal("full table did not drop an idle source to make room")
	}
	if _, ok := m.sources.Load(netip.MustParseAddr("10.0.0.1")); ok {
		t.Fatal("idle source survived the sweep")
	}
}

func TestSourceTrafficResetDropsClosedSources(t *testing.T) {
	m := &Manager{}
	closed := m.sourceCounterFor(sourceTestMetadata("10.0.0.1"))
	closed.addUpload(1)
	closed.release()
	live := m.sourceCounterFor(sourceTestMetadata("10.0.0.2"))
	m.ResetStatistic()
	if _, ok := m.sources.Load(netip.MustParseAddr("10.0.0.1")); ok {
		t.Fatal("reset kept a source without connections")
	}
	live.addUpload(7)
	if got := m.SourceTraffic(); len(got) != 1 || got[0].Upload != 7 {
		t.Fatalf("live source lost after reset: %+v", got)
	}
}

// Trackers come and go while sweeps run; a counter that is in use must never
// be dropped, so its traffic always shows up.
func TestSourceTrafficSweepRace(t *testing.T) {
	m := &Manager{}
	metadata := sourceTestMetadata("192.168.43.20")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				m.sweepSources(time.Now().Add(2*sourceIdleTTL), true)
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		counter := m.sourceCounterFor(metadata)
		counter.addDownload(1)
		if current, ok := m.sources.Load(netip.MustParseAddr("192.168.43.20")); !ok || current != counter {
			close(stop)
			wg.Wait()
			t.Fatalf("iteration %d: counter in use was dropped", i)
		}
		counter.release()
	}
	close(stop)
	wg.Wait()
	if n := m.sourceCount.Load(); n < 0 || n > 1 {
		t.Fatalf("source count drifted to %d", n)
	}
}

func BenchmarkSourceCounterAdd(b *testing.B) {
	counter := (&Manager{}).sourceCounterFor(sourceTestMetadata("192.168.43.20"))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			counter.addDownload(1500)
		}
	})
}
