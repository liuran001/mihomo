//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/tailscale/ipn"
)

func TestParseAdvertiseRoutes(t *testing.T) {
	routes, err := parseAdvertiseRoutes(TailscaleOption{AdvertiseRoutes: []string{" 10.0.0.7/24 ", "2001:db8::1/64"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0] != netip.MustParsePrefix("10.0.0.0/24") || routes[1] != netip.MustParsePrefix("2001:db8::/64") {
		t.Fatalf("unexpected routes: %v", routes)
	}

	if _, err := parseAdvertiseRoutes(TailscaleOption{AdvertiseRoutes: []string{"not-a-prefix"}}); err == nil {
		t.Fatal("invalid route accepted")
	}
}

func TestTailscaleAdvertisedRouteBoundary(t *testing.T) {
	tailscale := &Tailscale{advertisedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	if !tailscale.isAdvertisedRoute(netip.MustParseAddr("10.0.0.42")) {
		t.Fatal("advertised route was rejected")
	}
	if tailscale.isAdvertisedRoute(netip.MustParseAddr("10.0.1.42")) {
		t.Fatal("destination outside advertised route was accepted")
	}
}

func TestTailscaleBackendReady(t *testing.T) {
	if tailscaleBackendReady(ipn.NeedsLogin) || tailscaleBackendReady(ipn.Starting) || tailscaleBackendReady(ipn.Stopped) {
		t.Fatal("non-running backend reported ready")
	}
	if !tailscaleBackendReady(ipn.Running) {
		t.Fatal("running backend not reported ready")
	}
}

func TestTailscaleBackendStateTransitions(t *testing.T) {
	tailscale := &Tailscale{Base: NewBase(BaseOption{Name: "test"}), ctx: context.Background(), backendInitCh: make(chan struct{})}
	tailscale.observeBackendState(ipn.Running, false)
	if !tailscale.backendReady.Load() {
		t.Fatal("running backend was not marked ready")
	}
	tailscale.observeBackendState(ipn.Stopped, false)
	if tailscale.backendReady.Load() {
		t.Fatal("stopped backend remained ready")
	}
	tailscale.observeBackendState(ipn.Running, false)
	if !tailscale.backendReady.Load() {
		t.Fatal("backend did not recover to ready")
	}
}

func TestTailscaleExitNodeRetryCannotReviveStoppedBackend(t *testing.T) {
	tailscale := &Tailscale{Base: NewBase(BaseOption{Name: "test"}), ctx: context.Background(), backendInitCh: make(chan struct{})}
	applyStarted := make(chan struct{})
	allowApply := make(chan struct{})
	applyDone := make(chan struct{})
	tailscale.applyExitNodePrefsHook = func(ctx context.Context) error {
		close(applyStarted)
		defer close(applyDone)
		select {
		case <-allowApply:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	tailscale.backendIsRunningHook = func(context.Context) (bool, error) { return true, nil }
	tailscale.observeBackendState(ipn.Running, true)
	select {
	case <-applyStarted:
	case <-time.After(time.Second):
		t.Fatal("exit-node retry did not start")
	}
	tailscale.observeBackendState(ipn.Stopped, true)
	close(allowApply)
	select {
	case <-applyDone:
	case <-time.After(time.Second):
		t.Fatal("exit-node retry did not stop")
	}
	if tailscale.backendReady.Load() {
		t.Fatal("stale exit-node retry revived stopped backend")
	}
}
