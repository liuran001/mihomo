package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Capability probing lets proxy groups filter nodes by measured abilities
// (require-udp / require-ipv6) instead of name patterns. Results are cached
// globally by proxy identity with a TTL; unknown nodes stay selectable until a
// probe proves the capability missing, so groups never go dark while probes
// are still running.

const (
	capabilityProbeTimeout = 5 * time.Second
	capabilityOKTTL        = 30 * time.Minute
	capabilityFailTTL      = 10 * time.Minute

	// STUN binding request target for the UDP probe.
	capabilityStunServer = "stun.l.google.com:19302"
	// IPv6-only URL for the IPv6 egress probe.
	capabilityIPv6URL = "https://ipv6.google.com/generate_204"
)

type capabilityKind uint8

const (
	capabilityUDP capabilityKind = iota
	capabilityIPv6
)

type capabilityEntry struct {
	mu      sync.Mutex
	known   bool
	ok      bool
	expire  time.Time
	probing bool
}

type capabilityState struct {
	udp  capabilityEntry
	ipv6 capabilityEntry
}

var (
	capabilityCache sync.Map // proxy identity -> *capabilityState
	// limit concurrent probes so a large provider doesn't stampede
	capabilityProbeSem = make(chan struct{}, 8)
)

func capabilityStateFor(name string) *capabilityState {
	if v, ok := capabilityCache.Load(name); ok {
		return v.(*capabilityState)
	}
	v, _ := capabilityCache.LoadOrStore(name, &capabilityState{})
	return v.(*capabilityState)
}

// capabilityStateForProxy separates entries for same-named proxies coming
// from different adapter types or providers. Provider refreshes commonly
// reuse names, so the name alone is not a stable identity.
func capabilityStateForProxy(p C.Proxy) *capabilityState {
	return capabilityStateFor(capabilityCacheKey(p))
}

func capabilityCacheKey(p C.Proxy) string {
	info := p.ProxyInfo()
	return fmt.Sprintf("%s|%s|%s|%s", p.Name(), p.Type().String(), info.ProviderName, p.Addr())
}

// Capability verdicts. Unknown is a distinct state: it means no probe has
// finished yet, which ranks below a confirmed capability but above a
// confirmed failure.
const (
	capYes     = 1
	capUnknown = 0
	capNo      = -1
)

// stateOrProbe returns the cached verdict for this proxy, scheduling an async
// probe when nothing usable is cached. A stale verdict keeps being reported
// while the refresh runs.
func (s *capabilityState) stateOrProbe(p C.Proxy, kind capabilityKind) int {
	entry := &s.udp
	if kind == capabilityIPv6 {
		entry = &s.ipv6
	}
	entry.mu.Lock()
	fresh := entry.known && time.Now().Before(entry.expire)
	known, ok := entry.known, entry.ok
	if !fresh && !entry.probing {
		entry.probing = true
		go probeCapability(p, kind, entry)
	}
	entry.mu.Unlock()
	if !known {
		return capUnknown
	}
	if ok {
		return capYes
	}
	return capNo
}

func probeCapability(p C.Proxy, kind capabilityKind, entry *capabilityEntry) {
	// Do not queue one blocked goroutine per provider node. A later call will
	// retry after capacity is available, while this probe remains unknown.
	select {
	case capabilityProbeSem <- struct{}{}:
		defer func() { <-capabilityProbeSem }()
	default:
		entry.mu.Lock()
		entry.probing = false
		entry.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), capabilityProbeTimeout)
	defer cancel()

	var ok bool
	switch kind {
	case capabilityUDP:
		ok = probeUDP(ctx, p)
	case capabilityIPv6:
		// URLTest updates the proxy's global alive flag and delay history. A
		// capability probe is auxiliary telemetry and must not make a proxy
		// appear dead (or reset its health history), so use the non-mutating
		// status probe instead.
		_, ok, _ = p.StatusTest(ctx, capabilityIPv6URL)
	}

	ttl := capabilityOKTTL
	if !ok {
		ttl = capabilityFailTTL
	}
	entry.mu.Lock()
	entry.known = true
	entry.ok = ok
	entry.expire = time.Now().Add(ttl)
	entry.probing = false
	entry.mu.Unlock()

	kindName := "udp"
	if kind == capabilityIPv6 {
		kindName = "ipv6"
	}
	log.Debugln("[Capability] %s %s=%v", p.Name(), kindName, ok)
}

// probeUDP sends a STUN binding request through the proxy and waits for any
// response; a valid reply proves the node forwards UDP end to end.
func probeUDP(ctx context.Context, p C.Proxy) bool {
	host, portStr, err := net.SplitHostPort(capabilityStunServer)
	if err != nil {
		return false
	}
	ip, err := resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
	if err != nil {
		return false
	}
	var port uint16
	if v, err := netip.ParseAddrPort(net.JoinHostPort("0.0.0.0", portStr)); err == nil {
		port = v.Port()
	} else {
		return false
	}
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    host,
		DstIP:   ip.Unmap(),
		DstPort: port,
	}
	pc, err := p.ListenPacketContext(ctx, metadata)
	if err != nil {
		return false
	}
	defer func() { _ = pc.Close() }()

	// STUN binding request: type 0x0001, length 0, magic cookie, random txid
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
	if _, err = rand.Read(req[8:20]); err != nil {
		return false
	}
	txid := append([]byte(nil), req[8:20]...)

	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), port))
	deadline, _ := ctx.Deadline()
	_ = pc.SetDeadline(deadline)
	if _, err = pc.WriteTo(req, dst); err != nil {
		return false
	}
	buf := make([]byte, 512)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return false
		}
		if validSTUNBindingSuccess(buf[:n], txid) && validSTUNSource(src, dst) {
			return true
		}
	}
}

func validSTUNSource(src net.Addr, expected *net.UDPAddr) bool {
	got, ok := src.(*net.UDPAddr)
	if !ok || expected == nil {
		return false
	}
	return got.Port == expected.Port && got.IP.Equal(expected.IP)
}

func validSTUNBindingSuccess(message, txid []byte) bool {
	if len(message) < 20 || len(txid) != 12 {
		return false
	}
	if binary.BigEndian.Uint16(message[0:2]) != 0x0101 ||
		int(binary.BigEndian.Uint16(message[2:4])) != len(message)-20 ||
		binary.BigEndian.Uint32(message[4:8]) != 0x2112A442 ||
		!bytes.Equal(message[8:20], txid) {
		return false
	}
	return true
}

// Capability preferences only ever reorder a group, never shrink it. A node
// that lacks a preferred capability gets extra latency added when ranking, so
// it sinks below the nodes that have it while staying selectable as a last
// resort. That matters because the probes are themselves unreliable — the
// IPv6 probe target is reachable only when upstream IPv6 works — and a group
// that hard-filtered on a failed probe would go dark for reasons that have
// nothing to do with whether its nodes can carry traffic.
const (
	// capabilityMissingPenalty applies when a probe confirmed the capability
	// is absent. Large enough to lose against any healthy node that has it,
	// small enough that a fast node without it still beats a slow node with.
	capabilityMissingPenalty = 600
	// capabilityUnknownPenalty applies while a probe is still pending, so an
	// unprobed node ranks just behind a confirmed one instead of being
	// buried alongside confirmed failures.
	capabilityUnknownPenalty = 50
)

// CapabilityPenalty returns extra latency in milliseconds to add when ranking
// this proxy against a group's capability preferences, scheduling any probe
// that is missing or stale. Groups apply it where they already rank by delay;
// groups with an explicit user-chosen or configured order (select, fallback)
// deliberately ignore it, since a probe result must not silently rewrite what
// the user picked.
func CapabilityPenalty(p C.Proxy, preferUDP, preferIPv6 bool) uint16 {
	if p == nil || (!preferUDP && !preferIPv6) {
		return 0
	}
	state := capabilityStateForProxy(p)
	penalty := 0
	if preferUDP {
		penalty += capabilityPenaltyFor(state.stateOrProbe(p, capabilityUDP))
	}
	if preferIPv6 {
		penalty += capabilityPenaltyFor(state.stateOrProbe(p, capabilityIPv6))
	}
	return uint16(penalty)
}

func capabilityPenaltyFor(verdict int) int {
	switch verdict {
	case capYes:
		return 0
	case capNo:
		return capabilityMissingPenalty
	default:
		return capabilityUnknownPenalty
	}
}

// AddCapabilityPenalty adds the capability penalty to a measured delay,
// saturating instead of wrapping so a penalized node never sorts as fast.
func AddCapabilityPenalty(delay uint16, p C.Proxy, preferUDP, preferIPv6 bool) uint16 {
	penalty := CapabilityPenalty(p, preferUDP, preferIPv6)
	if penalty == 0 {
		return delay
	}
	if uint32(delay)+uint32(penalty) > 0xFFFF {
		return 0xFFFF
	}
	return delay + penalty
}
