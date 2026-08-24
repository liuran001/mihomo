package listener

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type stubInboundConfig struct{ name string }

func (c stubInboundConfig) Name() string { return c.name }

func (c stubInboundConfig) Equal(config C.InboundConfig) bool {
	other, ok := config.(stubInboundConfig)
	return ok && other.name == c.name
}

type stubInboundListener struct {
	name      string
	listens   int
	closes    int
	listenErr error
}

func (s *stubInboundListener) Name() string                 { return s.name }
func (s *stubInboundListener) Listen(tunnel C.Tunnel) error { s.listens++; return s.listenErr }
func (s *stubInboundListener) Close() error                 { s.closes++; return nil }
func (s *stubInboundListener) Address() string              { return "" }
func (s *stubInboundListener) RawAddress() string           { return "" }
func (s *stubInboundListener) Config() C.InboundConfig      { return stubInboundConfig{name: s.name} }

type stubStaleListener struct {
	stubInboundListener
	stale bool
}

func (s *stubStaleListener) Stale() bool { return s.stale }

func withInboundListeners(t *testing.T, listeners map[string]C.InboundListener) {
	t.Helper()
	previous := inboundListeners
	t.Cleanup(func() { inboundListeners = previous })
	inboundListeners = listeners
}

// A tun listener bakes the eBPF route exclusion into its device, and the patch
// loop walks a map: it can build that device before the eBPF inbound has
// published anything, and an unchanged tun section would never rebuild it again.
// Only the listeners that say they moved are restarted.
func TestRebuildStaleListenersRestartsOnlyWhatMoved(t *testing.T) {
	stale := &stubStaleListener{stale: true}
	current := &stubStaleListener{}
	plain := &stubInboundListener{}
	withInboundListeners(t, map[string]C.InboundListener{
		"tun-stale": stale,
		"tun":       current,
		"http":      plain,
	})

	rebuildStaleListeners(nil)

	if stale.closes != 1 || stale.listens != 1 {
		t.Fatalf("expected the stale listener to be closed and restarted once, got %d close(s) and %d listen(s)", stale.closes, stale.listens)
	}
	if _, ok := inboundListeners["tun-stale"]; !ok {
		t.Fatal("expected a restarted listener to stay registered")
	}
	if current.closes != 0 || current.listens != 0 {
		t.Fatal("expected a listener that did not move to be left alone")
	}
	if plain.closes != 0 || plain.listens != 0 {
		t.Fatal("expected a listener with no build state of its own to be left alone")
	}
}

// A listener that cannot come back is closed and gone. Leaving it registered
// would hand later reloads a dead listener that compares equal to its config and
// is therefore never rebuilt.
func TestRebuildStaleListenersDropsOneThatCannotRestart(t *testing.T) {
	broken := &stubStaleListener{stale: true}
	broken.listenErr = errors.New("device busy")
	withInboundListeners(t, map[string]C.InboundListener{"tun": broken})

	rebuildStaleListeners(nil)

	if broken.closes != 1 || broken.listens != 1 {
		t.Fatalf("expected one close and one failed listen, got %d and %d", broken.closes, broken.listens)
	}
	if _, ok := inboundListeners["tun"]; ok {
		t.Fatal("expected a listener that failed to restart to be dropped")
	}
}

// The rebuild has to be wired into the patch itself: a config that did not
// change makes the loop keep the running listener, and that is exactly the case
// where the state underneath it may have moved.
func TestPatchInboundListenersRebuildsAListenerItLeftAlone(t *testing.T) {
	running := &stubStaleListener{stale: true}
	running.name = "tun"
	withInboundListeners(t, map[string]C.InboundListener{"tun": running})

	replacement := &stubStaleListener{}
	replacement.name = "tun"
	PatchInboundListeners(map[string]C.InboundListener{"tun": replacement}, nil, true)

	if replacement.listens != 0 {
		t.Fatal("expected an unchanged config to keep the running listener rather than swap in a new one")
	}
	if running.closes != 1 || running.listens != 1 {
		t.Fatalf("expected the running listener to be restarted for the state that moved, got %d close(s) and %d listen(s)", running.closes, running.listens)
	}
}
