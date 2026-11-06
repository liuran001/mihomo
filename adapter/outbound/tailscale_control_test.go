//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/netmap"
	"github.com/metacubex/tailscale/types/persist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTailscaleStatusBeforeStart(t *testing.T) {
	ts := &Tailscale{
		Base:   &Base{name: "ts"},
		ctx:    context.Background(),
		option: TailscaleOption{Hostname: "phone", AuthKey: "tskey-test", Serve: []TailscaleServeOption{{Port: 80, Target: "http://127.0.0.1:8080"}}},
	}
	status := ts.TailscaleStatus(context.Background())
	assert.Equal(t, "ts", status["name"])
	assert.Equal(t, "NotStarted", status["state"])
	assert.Equal(t, false, status["started"])
	assert.Equal(t, true, status["authKey"])
	assert.Equal(t, []map[string]any{{"port": uint16(80), "target": "http://127.0.0.1:8080"}}, status["serve"])
	_, hasKey := status["authURL"]
	assert.False(t, hasKey)
	assert.Error(t, ts.TailscaleLogout(context.Background()))
}

func TestTailscaleStatusDoesNotWaitForStartup(t *testing.T) {
	outbound := &Tailscale{Base: &Base{name: "ts"}, ctx: context.Background()}
	outbound.startAccess.Lock()
	defer outbound.startAccess.Unlock()
	completed := make(chan map[string]any, 1)
	go func() { completed <- outbound.TailscaleStatus(context.Background()) }()
	select {
	case status := <-completed:
		assert.Equal(t, "ts", status["name"])
	case <-time.After(200 * time.Millisecond):
		t.Fatal("status waits on the startup lock instead of reading a snapshot")
	}
}

func TestTailscaleStatusUsesSelfOwnerAndImmutableSnapshot(t *testing.T) {
	outbound := &Tailscale{Base: &Base{name: "ts"}, ctx: context.Background()}
	outbound.serverStarted.Store(true)
	owner := &tailcfg.UserProfile{ID: 7, LoginName: "owner@example.com", DisplayName: "Owner"}
	other := &tailcfg.UserProfile{ID: 8, LoginName: "other@example.com"}
	self := &tailcfg.Node{User: owner.ID, Name: "phone.example.ts.net.", Hostinfo: (&tailcfg.Hostinfo{Hostname: "phone"}).View(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}
	state := ipn.Running
	outbound.observeControlNotify(ipn.Notify{State: &state, NetMap: &netmap.NetworkMap{
		SelfNode: self.View(), Domain: "team.example.com", UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{owner.ID: owner.View(), other.ID: other.View()},
	}})
	status := outbound.TailscaleStatus(context.Background())
	require.Equal(t, owner.LoginName, status["login"])
	require.Equal(t, "team.example.com", status["tailnet"])
	identity := status["self"].(map[string]any)
	assert.Equal(t, []string{"100.64.0.1"}, identity["ips"])
	identity["ips"].([]string)[0] = "changed"
	assert.Equal(t, []string{"100.64.0.1"}, outbound.TailscaleStatus(context.Background())["self"].(map[string]any)["ips"])
	self.User = other.ID
	outbound.observeControlNotify(ipn.Notify{SelfChange: self})
	assert.NotContains(t, outbound.TailscaleStatus(context.Background()), "login")
	prefs := (&ipn.Prefs{Persist: &persist.Persist{UserProfile: *other}}).View()
	outbound.observeControlNotify(ipn.Notify{Prefs: &prefs})
	assert.Equal(t, other.LoginName, outbound.TailscaleStatus(context.Background())["login"])
	state = ipn.NeedsLogin
	loginURL := "https://login.tailscale.com/a/test"
	outbound.observeControlNotify(ipn.Notify{State: &state, BrowseToURL: &loginURL})
	status = outbound.TailscaleStatus(context.Background())
	assert.NotContains(t, status, "self")
	assert.NotContains(t, status, "login")
	assert.NotContains(t, status, "tailnet")
	assert.Equal(t, loginURL, status["authURL"])
	state = ipn.Running
	outbound.observeControlNotify(ipn.Notify{State: &state})
	assert.NotContains(t, outbound.TailscaleStatus(context.Background()), "authURL")
}

func TestTailscaleStatusDoesNotWaitForBackendState(t *testing.T) {
	outbound := &Tailscale{Base: &Base{name: "ts"}, ctx: context.Background()}
	outbound.serverStarted.Store(true)
	state := ipn.Running
	outbound.observeControlNotify(ipn.Notify{State: &state})
	outbound.backendStateAccess.Lock()
	defer outbound.backendStateAccess.Unlock()
	completed := make(chan map[string]any, 1)
	go func() { completed <- outbound.TailscaleStatus(context.Background()) }()
	select {
	case status := <-completed:
		assert.Equal(t, "Running", status["state"])
	case <-time.After(200 * time.Millisecond):
		t.Fatal("status waits on the data-plane readiness lock")
	}
}

func TestTailscaleLoginStartupTimeoutSharesOneAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	var attempts atomic.Int32
	outbound := &Tailscale{Base: &Base{name: "ts"}, ctx: ctx,
		startServerHook: func() error {
			if attempts.Add(1) == 1 {
				close(entered)
			}
			<-release
			return errors.New("startup unavailable")
		}, closeServerHook: func() error { return nil },
	}
	t.Cleanup(func() { close(release) })
	var callers sync.WaitGroup
	for range 16 {
		callers.Go(func() {
			_, err := outbound.TailscaleLogin(context.Background(), 50*time.Millisecond)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		})
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("startup did not begin")
	}
	completed := make(chan struct{})
	go func() { callers.Wait(); close(completed) }()
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("login deadline did not cover startup")
	}
	assert.Equal(t, int32(1), attempts.Load())
	assert.ErrorContains(t, outbound.TailscaleLogout(context.Background()), "in progress")
}

func TestTailscaleStatusConcurrentNotifications(t *testing.T) {
	outbound := &Tailscale{Base: &Base{name: "ts"}, ctx: context.Background()}
	outbound.serverStarted.Store(true)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				state := ipn.Running
				outbound.observeControlNotify(ipn.Notify{State: &state})
				outbound.TailscaleStatus(context.Background())
			}
		})
	}
	workers.Wait()
}

func BenchmarkTailscaleControlStatus(b *testing.B) {
	outbound := &Tailscale{Base: &Base{name: "ts"}, ctx: context.Background()}
	outbound.serverStarted.Store(true)
	outbound.startAccess.Lock()
	defer outbound.startAccess.Unlock()
	b.ReportAllocs()
	for b.Loop() {
		outbound.TailscaleStatus(context.Background())
	}
}
