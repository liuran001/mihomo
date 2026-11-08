package statistic

import (
	"net/netip"
	"sort"
	stdatomic "sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

// Per-source traffic, so a dashboard can show how much each LAN device sent
// through the core. A connection resolves its source counter once when it is
// tracked; afterwards each read or write costs one extra atomic add next to
// the manager totals it already updates. Reading the counters never walks the
// connection table, and closing a connection does no extra work.

// maxTrackedSources bounds the counter table. Sources past it are simply not
// counted per source (they still count in the manager totals).
const maxTrackedSources = 4096

type sourceCounter struct {
	upload   stdatomic.Int64
	download stdatomic.Int64
}

func (c *sourceCounter) addUpload(n int64) {
	if c != nil && n > 0 {
		c.upload.Add(n)
	}
}

func (c *sourceCounter) addDownload(n int64) {
	if c != nil && n > 0 {
		c.download.Add(n)
	}
}

// sourceCounterFor returns the counter for the metadata's source address, or
// nil when the source is unknown or the table is full.
func (m *Manager) sourceCounterFor(metadata *C.Metadata) *sourceCounter {
	if metadata == nil || !metadata.SrcIP.IsValid() {
		return nil
	}
	source := metadata.SrcIP.Unmap().WithZone("")
	if counter, ok := m.sources.Load(source); ok {
		return counter
	}
	if m.sourceCount.Load() >= maxTrackedSources {
		return nil
	}
	counter, loaded := m.sources.LoadOrStore(source, &sourceCounter{})
	if !loaded {
		m.sourceCount.Add(1)
	}
	return counter
}

// SourceTraffic is the traffic of one source address since the core started
// or the statistics were reset.
type SourceTraffic struct {
	Source   netip.Addr `json:"source"`
	Upload   int64      `json:"upload"`
	Download int64      `json:"download"`
}

func (m *Manager) SourceTraffic() []SourceTraffic {
	result := make([]SourceTraffic, 0, m.sourceCount.Load())
	m.sources.Range(func(source netip.Addr, counter *sourceCounter) bool {
		upload, download := counter.upload.Load(), counter.download.Load()
		if upload != 0 || download != 0 {
			result = append(result, SourceTraffic{Source: source, Upload: upload, Download: download})
		}
		return true
	})
	sort.Slice(result, func(i, j int) bool { return result[i].Source.Less(result[j].Source) })
	return result
}

// resetSources zeroes the counters in place: live connections keep pointers
// to them, so dropping the table would lose their later traffic.
func (m *Manager) resetSources() {
	m.sources.Range(func(_ netip.Addr, counter *sourceCounter) bool {
		counter.upload.Store(0)
		counter.download.Store(0)
		return true
	})
}
