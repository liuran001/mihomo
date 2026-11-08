package statistic

import (
	"net/netip"
	"testing"

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

func BenchmarkSourceCounterAdd(b *testing.B) {
	counter := (&Manager{}).sourceCounterFor(sourceTestMetadata("192.168.43.20"))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			counter.addDownload(1500)
		}
	})
}
