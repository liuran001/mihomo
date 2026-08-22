//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"
	"time"
)

// udp-timeout is documented and parsed as SECONDS by every other listener
// (see listener/sing_tun/server.go, which does `time.Second * time.Duration(v)`).
// Reading it as a bare time.Duration treats it as nanoseconds, which silently
// collapses the sweeper: udpClientTable.sweep would consider every client idle
// on the very first tick and tear down live sessions along with their eBPF
// redirect entries.
func TestResolveUDPTimeoutUsesSeconds(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		configured int64
		want       time.Duration
	}{
		{name: "unset falls back", configured: 0, want: 5 * time.Minute},
		{name: "negative falls back", configured: -1, want: 5 * time.Minute},
		{name: "typical value is seconds", configured: 300, want: 5 * time.Minute},
		{name: "one minute", configured: 60, want: time.Minute},
		{name: "below floor is clamped", configured: 1, want: minimumUDPTimeout},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := resolveUDPTimeout(testCase.configured); got != testCase.want {
				t.Fatalf("resolveUDPTimeout(%d) = %v, want %v", testCase.configured, got, testCase.want)
			}
		})
	}
}

// The periodic loop derives both its tick interval and the map stale-age from
// udpTimeout. Pin the properties that keep a live session from being swept:
// the sweep must run strictly more often than the idle timeout, and the eBPF
// stale-age must be strictly longer than it.
func TestResolveUDPTimeoutKeepsSweeperCoherent(t *testing.T) {
	for _, configured := range []int64{0, 1, 5, 60, 300, 3600} {
		timeout := resolveUDPTimeout(configured)

		interval := timeout / 2
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
		if interval > 30*time.Second {
			interval = 30 * time.Second
		}
		if interval > timeout {
			t.Errorf("udp-timeout %d: sweep interval %v exceeds the idle timeout %v, so a live client is evicted before it can be refreshed",
				configured, interval, timeout)
		}

		maxAge := 2 * timeout
		if maxAge < 30*time.Second {
			maxAge = 30 * time.Second
		}
		if maxAge <= timeout {
			t.Errorf("udp-timeout %d: eBPF stale-age %v is not longer than the idle timeout %v",
				configured, maxAge, timeout)
		}
	}
}
