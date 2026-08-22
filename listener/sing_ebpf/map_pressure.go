//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

// The redirect and flow maps are the only unbounded-by-traffic state the eBPF
// datapath keeps. When one of them fills up, new flows either lose their token
// (fixed hash maps return -E2BIG and the connection is refused) or evict a
// live entry (LRU maps), and in both cases the symptom the user sees is
// traffic that stalls for no visible reason. The capacity was always tracked --
// the sweepers compute it on every pass -- it was simply never reported, so an
// operator had no way to tell a saturated map from a healthy one until flows
// started dying. These thresholds turn that into a log line instead.
const (
	// mapPressureWarnRatio is where a map stops having useful headroom.
	mapPressureWarnRatio = 0.85
	// mapPressureClearRatio adds hysteresis so a map hovering at the threshold
	// does not alternate between warning and recovery notices.
	mapPressureClearRatio = 0.70
	// mapPressureInterval keeps a persistently full map from flooding the log.
	mapPressureInterval = 5 * time.Minute
)

type mapPressureWatcher struct {
	limiter  warningLimiter
	warned   bool
	capacity uint32
}

func newMapPressureWatcher() *mapPressureWatcher {
	watcher := &mapPressureWatcher{}
	watcher.limiter.interval = mapPressureInterval
	return watcher
}

// observe reports usage for one map. It returns quietly when the backend has
// not finished a full accounting pass yet: a partial count would read as a
// sudden drop to zero and clear a warning that still applies.
func (w *mapPressureWatcher) observe(logger warningLogger, name string, usage ECommon.MapUsage, err error) {
	if w == nil || err != nil || usage.Capacity == 0 {
		return
	}
	w.capacity = usage.Capacity
	ratio := float64(usage.Entries) / float64(usage.Capacity)
	switch {
	case ratio >= mapPressureWarnRatio:
		w.warned = true
		w.limiter.warn(
			logger,
			"map ", name, " is ",
			formatPercent(ratio), " full (", usage.Entries, "/", usage.Capacity,
			"); raise its state-capacity or expect stalled flows",
		)
	case w.warned && ratio <= mapPressureClearRatio:
		w.warned = false
		logger(
			"[EBPF] map %s recovered to %s full (%d/%d)",
			name, formatPercent(ratio), usage.Entries, usage.Capacity,
		)
	}
}

func formatPercent(ratio float64) string {
	percent := int(ratio*1000 + 0.5)
	whole := percent / 10
	fraction := percent % 10
	return itoa(whole) + "." + itoa(fraction) + "%"
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [12]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
