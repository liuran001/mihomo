//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"strings"
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"

	"golang.org/x/sys/unix"
)

func collectingLogger(sink *[]string) warningLogger {
	return func(format string, args ...any) {
		*sink = append(*sink, format)
		_ = args
	}
}

func usage(entries, capacity uint32) ECommon.MapUsage {
	return ECommon.MapUsage{Entries: entries, Capacity: capacity}
}

func TestMapPressureWatcherWarnsOnlyWhenSaturated(t *testing.T) {
	t.Parallel()
	var lines []string
	watcher := newMapPressureWatcher()
	logger := collectingLogger(&lines)

	watcher.observe(logger, "m", usage(100, 1000), nil)
	if len(lines) != 0 {
		t.Fatalf("10%% full should stay quiet, got %v", lines)
	}

	watcher.observe(logger, "m", usage(900, 1000), nil)
	if len(lines) != 1 {
		t.Fatalf("90%% full should warn once, got %v", lines)
	}
	if !strings.Contains(lines[0], "%v") {
		t.Fatalf("warning should be emitted through the limiter format: %q", lines[0])
	}
}

func TestMapPressureWatcherHysteresis(t *testing.T) {
	t.Parallel()
	var lines []string
	watcher := newMapPressureWatcher()
	logger := collectingLogger(&lines)

	watcher.observe(logger, "m", usage(900, 1000), nil)
	// Between the clear and warn ratios: neither a repeat warning nor a
	// recovery notice, otherwise a map parked at 80% would alternate forever.
	watcher.observe(logger, "m", usage(800, 1000), nil)
	if len(lines) != 1 {
		t.Fatalf("80%% sits inside the hysteresis band, got %v", lines)
	}
	if !watcher.warned {
		t.Fatal("watcher cleared its warning inside the hysteresis band")
	}

	watcher.observe(logger, "m", usage(500, 1000), nil)
	if len(lines) != 2 {
		t.Fatalf("dropping below the clear ratio should report recovery, got %v", lines)
	}
	if watcher.warned {
		t.Fatal("watcher stayed in the warned state after recovering")
	}

	// Recovering twice must not log twice.
	watcher.observe(logger, "m", usage(400, 1000), nil)
	if len(lines) != 2 {
		t.Fatalf("recovery should be reported once, got %v", lines)
	}
}

func TestMapPressureWatcherIgnoresUnknownUsage(t *testing.T) {
	t.Parallel()
	var lines []string
	watcher := newMapPressureWatcher()
	logger := collectingLogger(&lines)

	// A backend that has not completed an accounting pass reports ENODATA with
	// a zero entry count. Treating that as "empty" would clear a live warning.
	watcher.observe(logger, "m", usage(1000, 1000), nil)
	watcher.observe(logger, "m", usage(0, 1000), unix.ENODATA)
	if !watcher.warned {
		t.Fatal("ENODATA cleared the warning; a partial count is not a recovery")
	}
	if len(lines) != 1 {
		t.Fatalf("ENODATA should not log, got %v", lines)
	}

	// A zero capacity means the map is not configured at all.
	watcher.observe(logger, "m", usage(0, 0), nil)
	if len(lines) != 1 {
		t.Fatalf("zero capacity should not log, got %v", lines)
	}
}

func TestFormatPercent(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		ratio    float64
		expected string
	}{
		{0, "0.0%"},
		{0.5, "50.0%"},
		{0.8523, "85.2%"},
		{0.9923, "99.2%"},
		{1, "100.0%"},
	} {
		if got := formatPercent(testCase.ratio); got != testCase.expected {
			t.Fatalf("formatPercent(%v) = %q, want %q", testCase.ratio, got, testCase.expected)
		}
	}
}
