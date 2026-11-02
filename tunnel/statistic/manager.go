package statistic

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
		trafficWake:   make(chan struct{}, 1),
	}

	go DefaultManager.handle(context.Background(), time.Second)
}

type Manager struct {
	connections   xsync.Map[string, Tracker]
	smartTarget   xsync.Map[string, *xsync.Map[string, bool]]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	pid           int32
	memory        atomic.Uint64
	memoryMu      sync.Mutex
	memoryUpdated time.Time
	trafficActive atomic.Bool
	trafficWake   chan struct{}

	// uploadWait is closed by the next upload once UploadSignal armed it.
	// uploadArmed lets the write path skip the lock while nobody waits.
	uploadArmed  atomic.Bool
	uploadWaitMu sync.Mutex
	uploadWait   chan struct{}
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
	m.joinSmartTarget(c)
	// Bytes counted before tracking began are already stamped; announce them
	// as an upload of their own, after the connection is visible to Range.
	if c.Info().LastUpload.Load() != 0 {
		m.signalUpload()
	}
}

// UploadSignal returns a channel closed by the next upload on any tracked
// connection. Arm it before scanning connections: an upload either lands in the
// scan or closes the channel, so a waiter that found nothing to do never misses
// the one that gives it work.
func (m *Manager) UploadSignal() <-chan struct{} {
	m.uploadWaitMu.Lock()
	defer m.uploadWaitMu.Unlock()
	if m.uploadWait == nil {
		m.uploadWait = make(chan struct{})
		m.uploadArmed.Store(true)
	}
	return m.uploadWait
}

func (m *Manager) noteUpload(stamp *atomic.Int64, n int64) {
	noteTraffic(stamp, n)
	if n > 0 {
		m.signalUpload()
	}
}

func (m *Manager) signalUpload() {
	if !m.uploadArmed.Load() {
		return
	}
	m.uploadWaitMu.Lock()
	if m.uploadArmed.CompareAndSwap(true, false) {
		close(m.uploadWait)
		m.uploadWait = nil
	}
	m.uploadWaitMu.Unlock()
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
	m.leaveSmartTarget(c)
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
	if size != 0 {
		m.wakeTraffic()
	}
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
	if size != 0 {
		m.wakeTraffic()
	}
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory.Load()
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory.Load(),
	}
}

func (m *Manager) updateMemory() {
	m.memoryMu.Lock()
	defer m.memoryMu.Unlock()
	// Multiple dashboards share one on-demand sample. No background timer is
	// needed when nobody is watching, and failed queries are rate limited too.
	if time.Since(m.memoryUpdated) < time.Second {
		return
	}
	m.memoryUpdated = time.Now()
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory.Store(stat.RSS)
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) wakeTraffic() {
	if m.trafficWake != nil && !m.trafficActive.Load() && m.trafficActive.CompareAndSwap(false, true) {
		select {
		case m.trafficWake <- struct{}{}:
		default:
		}
	}
}

func (m *Manager) handle(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(interval)
	timer.Stop()
	defer timer.Stop()
	var tick <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.trafficWake:
			if tick == nil {
				timer.Reset(interval)
				tick = timer.C
			}
		case <-tick:
			up, down := m.uploadTemp.Swap(0), m.downloadTemp.Swap(0)
			m.uploadBlip.Store(up)
			m.downloadBlip.Store(down)
			if up != 0 || down != 0 {
				timer.Reset(interval)
				continue
			}
			// Publish dormancy before checking for traffic that raced the
			// swaps. A writer either wakes us itself or is caught here.
			tick = nil
			m.trafficActive.Store(false)
			if m.uploadTemp.Load() != 0 || m.downloadTemp.Load() != 0 {
				m.wakeTraffic()
			}
		}
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}

func (m *Manager) joinSmartTarget(c Tracker) {
	info := c.Info()
	target := info.Metadata.SmartTarget

	if target == "" {
		return
	}

	id := c.ID()

	result, _ := m.smartTarget.LoadOrStoreFn(target, func() *xsync.Map[string, bool] {
		return xsync.NewMap[string, bool]()
	})
	result.Store(id, true)
}

func (m *Manager) leaveSmartTarget(c Tracker) {
	info := c.Info()
	target := info.Metadata.SmartTarget

	if target == "" {
		return
	}

	id := c.ID()

	m.smartTarget.Compute(target, func(result *xsync.Map[string, bool], loaded bool) (*xsync.Map[string, bool], xsync.ComputeOp) {
		if loaded {
			result.Delete(id)
			if result.IsEmpty() {
				return result, xsync.DeleteOp
			}
			return result, xsync.UpdateOp
		}
		return result, xsync.CancelOp
	})
}

func (m *Manager) RangeSmartTarget(target string, fn func(id string) bool) {
	if result, ok := m.smartTarget.Load(target); ok {
		result.Range(func(id string, _ bool) bool {
			return fn(id)
		})
	}
}
