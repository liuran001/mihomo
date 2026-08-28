package tunnel

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// stubProxy is the smallest thing that satisfies C.Proxy. ebpfBypassedDirect
// only looks the proxy up and hands it back, so the embedded nil interface is
// never touched.
type stubProxy struct {
	C.Proxy
	name string
}

func (s *stubProxy) Name() string { return s.name }

// installDirectProxy publishes a DIRECT entry and restores the previous table,
// because proxies is process-wide state shared with every other test.
func installDirectProxy(t *testing.T) *stubProxy {
	t.Helper()
	previous := proxies
	t.Cleanup(func() { proxies = previous })
	direct := &stubProxy{name: "DIRECT"}
	proxies = map[string]C.Proxy{"DIRECT": direct}
	return direct
}

func setMode(t *testing.T, m TunnelMode) {
	t.Helper()
	previous := mode.Load()
	t.Cleanup(func() { mode.Store(previous) })
	mode.Store(m)
}

// bypassPrefix publishes one bypassed prefix that asks for direct handling, and
// withdraws it when the test ends: the policy is a union across publishers, so
// a leaked entry would follow the next test.
func bypassPrefix(t *testing.T, prefix string) {
	t.Helper()
	p := resolver.NewEBPFBypassPublisher()
	t.Cleanup(p.Close)
	p.Publish(nil, []netip.Prefix{netip.MustParsePrefix(prefix)}, nil, true)
}

func tunMetadata(addr string) *C.Metadata {
	metadata := &C.Metadata{Type: C.TUN, DstPort: 443}
	if addr != "" {
		metadata.DstIP = netip.MustParseAddr(addr)
	}
	return metadata
}

func TestEBPFBypassedDirectHonoursTheBypass(t *testing.T) {
	direct := installDirectProxy(t)
	bypassPrefix(t, "10.0.0.0/8")

	proxy, ok := ebpfBypassedDirect(tunMetadata("10.1.2.3"), Rule)
	if !ok {
		t.Fatal("expected a bypassed TUN destination to be connected directly")
	}
	if proxy != C.Proxy(direct) {
		t.Fatalf("expected the DIRECT proxy, got %v", proxy)
	}

	// A destination outside the policy still goes through the rules.
	if _, ok = ebpfBypassedDirect(tunMetadata("203.0.113.7"), Rule); ok {
		t.Fatal("expected a destination outside the bypass policy to be matched against the rules")
	}
}

// Global and direct mode are standing instructions about where every flow goes.
// Answering one of them with DIRECT would contradict the user, and logMetadata
// would report a nil rule under global mode as "using GLOBAL" -- naming the one
// proxy such a connection did not use.
func TestEBPFBypassedDirectOnlyAppliesInRuleMode(t *testing.T) {
	installDirectProxy(t)
	bypassPrefix(t, "10.0.0.0/8")

	for _, m := range []TunnelMode{Global, Direct} {
		if _, ok := ebpfBypassedDirect(tunMetadata("10.1.2.3"), m); ok {
			t.Fatalf("expected %s mode to decide the proxy itself", m)
		}
	}
}

// Every other inbound was addressed on purpose, so its traffic is a request to
// route something rather than a side effect of a route the bypass tried to
// leave alone.
func TestEBPFBypassedDirectRequiresATunSource(t *testing.T) {
	installDirectProxy(t)
	bypassPrefix(t, "10.0.0.0/8")

	metadata := tunMetadata("10.1.2.3")
	metadata.Type = C.SOCKS5
	if _, ok := ebpfBypassedDirect(metadata, Rule); ok {
		t.Fatal("expected a non-TUN inbound to be matched against the rules")
	}
}

// A config without a DIRECT proxy must fall through rather than return a nil
// proxy that the dialer would then dereference.
func TestEBPFBypassedDirectWithoutADirectProxy(t *testing.T) {
	previous := proxies
	t.Cleanup(func() { proxies = previous })
	proxies = map[string]C.Proxy{}
	bypassPrefix(t, "10.0.0.0/8")

	if _, ok := ebpfBypassedDirect(tunMetadata("10.1.2.3"), Rule); ok {
		t.Fatal("expected no direct decision when the config has no DIRECT proxy")
	}
}

// Without a running eBPF inbound nothing is bypassed, so the hook must stay out
// of the way entirely.
func TestEBPFBypassedDirectWithoutAPolicy(t *testing.T) {
	installDirectProxy(t)

	if _, ok := ebpfBypassedDirect(tunMetadata("10.1.2.3"), Rule); ok {
		t.Fatal("expected no direct decision without a published bypass policy")
	}
}

// logMetadata names the mode the connection was decided under, not whichever one
// is set by the time the line is written. Without that, flipping the mode from
// the REST API renames connections that were already dialled -- and a bypassed
// connection, which carries no rule, would be reported as "using GLOBAL" when it
// went out through DIRECT.
func TestLogMetadataNamesTheDecidedMode(t *testing.T) {
	setMode(t, Global)

	subscription := log.Subscribe()
	defer log.UnSubscribe(subscription)

	// rule is nil and the mode branches never touch the connection, so the
	// remote conn a real caller would pass is not needed here.
	metadata := tunMetadata("10.0.0.1")
	logMetadata(metadata, nil, Direct, nil)

	// The log bus is process-wide, and the observable hands an event it has
	// already taken off the channel to whoever is subscribed by the time it
	// reaches its lock -- so a line another test emitted just before this one
	// subscribed can arrive first. Claim our own line by the destination it was
	// logged for instead of trusting whatever turns up first.
	destination := metadata.RemoteAddress()
	timeout := time.After(5 * time.Second)
	var unrelated []string
	for {
		select {
		case event, ok := <-subscription:
			if !ok {
				t.Fatalf("log subscription closed before a line for %s arrived", destination)
			}
			if !strings.Contains(event.Payload, destination) {
				unrelated = append(unrelated, event.Payload)
				continue
			}
			if !strings.Contains(event.Payload, "using DIRECT") {
				t.Fatalf("expected the line to name the mode the connection was decided under, got %q", event.Payload)
			}
			return
		case <-timeout:
			t.Fatalf("timed out waiting for the log line for %s; unrelated lines seen: %q", destination, unrelated)
		}
	}
}
