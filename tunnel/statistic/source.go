package statistic

import (
	"net/netip"
	"sort"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
)

// Per-source traffic, so a dashboard can show how much each LAN device sent
// through the core. A connection resolves its source counter once when it is
// tracked; afterwards each read or write costs one extra atomic add next to
// the manager totals it already updates. Reading the counters never walks the
// connection table; closing a connection only releases its counter reference.
//
// Sources that stop connecting (devices that left, rotated IPv6 temporary
// addresses) are dropped once no connection uses them and they have been idle
// for sourceIdleTTL. There is no timer: the sweep runs at most once per
// sourceSweepInterval, when the counters are read or the table is full.

const (
	// maxTrackedSources bounds the counter table. Sources past it are not
	// counted per source (they still count in the manager totals).
	maxTrackedSources = 4096
	// sourceIdleTTL is how long a source without live connections keeps its
	// totals before it is dropped.
	sourceIdleTTL = time.Hour
	// sourceSweepInterval rate-limits sweeps for idle sources.
	sourceSweepInterval = time.Minute
)

type sourceCounter struct {
	upload   stdatomic.Int64
	download stdatomic.Int64
	// refs counts live trackers holding the counter. It is only increased
	// inside a Compute on the table, which is also where idle counters are
	// deleted, so a deleted counter is never handed out again.
	refs stdatomic.Int32
	// idleSince is the unix nano time of the last release (or creation).
	idleSince stdatomic.Int64
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

// release drops one tracker reference. The idle time is stored first so a
// sweep that sees refs reach zero also sees a fresh idle time.
func (c *sourceCounter) release() {
	if c == nil {
		return
	}
	c.idleSince.Store(time.Now().UnixNano())
	c.refs.Add(-1)
}

// sourceCounterFor returns the counter for the metadata's source address with
// one reference taken (release it when the tracker closes), or nil when the
// source is unknown or the table is full.
func (m *Manager) sourceCounterFor(metadata *C.Metadata) *sourceCounter {
	if metadata == nil || !metadata.SrcIP.IsValid() {
		return nil
	}
	source := metadata.SrcIP.Unmap().WithZone("")
	if m.sourceCount.Load() >= maxTrackedSources {
		if _, ok := m.sources.Load(source); !ok {
			m.sweepSources(time.Now(), false)
		}
	}
	counter, _ := m.sources.Compute(source, func(old *sourceCounter, loaded bool) (*sourceCounter, xsync.ComputeOp) {
		if loaded {
			old.refs.Add(1)
			return old, xsync.CancelOp
		}
		if m.sourceCount.Load() >= maxTrackedSources {
			return nil, xsync.CancelOp
		}
		counter := &sourceCounter{}
		counter.refs.Store(1)
		counter.idleSince.Store(time.Now().UnixNano())
		m.sourceCount.Add(1)
		return counter, xsync.UpdateOp
	})
	return counter
}

// sweepSources drops sources without live connections that have been idle
// for sourceIdleTTL, or all sources without live connections when all is
// set. Unless all is set it runs at most once per sourceSweepInterval.
func (m *Manager) sweepSources(now time.Time, all bool) {
	nowNano := now.UnixNano()
	if !all {
		last := m.sourceSweep.Load()
		if (last != 0 && nowNano-last < int64(sourceSweepInterval)) || !m.sourceSweep.CompareAndSwap(last, nowNano) {
			return
		}
	}
	deadline := nowNano - int64(sourceIdleTTL)
	idle := func(counter *sourceCounter) bool {
		return counter.refs.Load() <= 0 && (all || counter.idleSince.Load() <= deadline)
	}
	m.sources.Range(func(source netip.Addr, counter *sourceCounter) bool {
		if !idle(counter) {
			return true
		}
		// Recheck under the bucket lock: a new tracker may have taken the
		// counter since Range read it.
		m.sources.Compute(source, func(old *sourceCounter, loaded bool) (*sourceCounter, xsync.ComputeOp) {
			if !loaded || !idle(old) {
				return old, xsync.CancelOp
			}
			m.sourceCount.Add(-1)
			return nil, xsync.DeleteOp
		})
		return true
	})
}

// SourceTraffic is the traffic of one source address since the core started,
// the statistics were reset, or the source was last dropped as idle.
type SourceTraffic struct {
	Source   netip.Addr `json:"source"`
	Upload   int64      `json:"upload"`
	Download int64      `json:"download"`
}

func (m *Manager) SourceTraffic() []SourceTraffic {
	m.sweepSources(time.Now(), false)
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

// resetSources zeroes the counters in place (live connections keep pointers
// to them) and drops sources that have no live connection.
func (m *Manager) resetSources() {
	m.sources.Range(func(_ netip.Addr, counter *sourceCounter) bool {
		counter.upload.Store(0)
		counter.download.Store(0)
		return true
	})
	m.sweepSources(time.Now(), true)
}
