package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// lastUsed lets the opportunistic cache sweep remove identities that are
	// no longer present after a provider refresh. TTLs invalidate verdicts but
	// otherwise do not reclaim the sync.Map key itself.
	lastUsed atomic.Int64
}

var (
	capabilityCache          sync.Map // proxy identity -> *capabilityState
	capabilityCacheSweepRun  atomic.Uint32
	capabilityCacheSweepNext atomic.Int64
	// limit concurrent probes so a large provider doesn't stampede
	capabilityProbeSem = make(chan struct{}, 8)
)

const (
	capabilityCacheSweepInterval = 5 * time.Minute
	capabilityCacheIdleTTL       = time.Hour
)

func capabilityStateFor(name string) *capabilityState {
	now := time.Now()
	if v, ok := capabilityCache.Load(name); ok {
		state := v.(*capabilityState)
		state.lastUsed.Store(now.UnixNano())
		maybeSweepCapabilityCache(now)
		return state
	}
	state := &capabilityState{}
	state.lastUsed.Store(now.UnixNano())
	v, _ := capabilityCache.LoadOrStore(name, state)
	state = v.(*capabilityState)
	state.lastUsed.Store(now.UnixNano())
	maybeSweepCapabilityCache(now)
	return state
}

func maybeSweepCapabilityCache(now time.Time) {
	nowNS := now.UnixNano()
	next := capabilityCacheSweepNext.Load()
	if next != 0 && nowNS < next {
		return
	}
	if !capabilityCacheSweepNext.CompareAndSwap(next, now.Add(capabilityCacheSweepInterval).UnixNano()) {
		return
	}
	// Range and per-entry locking can be expensive with large providers. Never
	// make the caller that is selecting a proxy pay that cost. The sweep is
	// scheduled at a low fixed cadence instead of once per N candidate visits,
	// which otherwise scales with provider size and connection churn.
	if !capabilityCacheSweepRun.CompareAndSwap(0, 1) {
		return
	}
	go func() {
		defer capabilityCacheSweepRun.Store(0)
		sweepNow := time.Now()
		cutoff := sweepNow.Add(-capabilityCacheIdleTTL).UnixNano()
		capabilityCache.Range(func(key, value any) bool {
			state, ok := value.(*capabilityState)
			if !ok || state.lastUsed.Load() >= cutoff {
				return true
			}
			state.udp.mu.Lock()
			udpIdle := !state.udp.probing && (!state.udp.known || !sweepNow.Before(state.udp.expire))
			state.udp.mu.Unlock()
			state.ipv6.mu.Lock()
			ipv6Idle := !state.ipv6.probing && (!state.ipv6.known || !sweepNow.Before(state.ipv6.expire))
			state.ipv6.mu.Unlock()
			if udpIdle && ipv6Idle {
				capabilityCache.CompareAndDelete(key, state)
			}
			return true
		})
	}()
}

// capabilityStateForProxy separates entries for same-named proxies coming
// from different adapter types or providers. Provider refreshes commonly
// reuse names, so the name alone is not a stable identity.
func capabilityStateForProxy(p C.Proxy) *capabilityState {
	return capabilityStateFor(capabilityCacheKey(p))
}

func capabilityCacheKey(p C.Proxy) string {
	return ProxyIdentity(p)
}

// ProxyIdentity returns an unambiguous, stable identity for a proxy. Length
// prefixes are intentional: names, provider names, and addresses are user
// supplied and may contain any separator character.
func ProxyIdentity(p C.Proxy) string {
	if p == nil {
		return ""
	}
	info := p.ProxyInfo()
	parts := [...]string{p.Name(), p.Type().String(), info.ProviderName, p.Addr()}
	var identity strings.Builder
	for _, part := range parts {
		identity.WriteString(strconv.Itoa(len(part)))
		identity.WriteByte(':')
		identity.WriteString(part)
	}
	return identity.String()
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
	deadline, hasDeadline := ctx.Deadline()
	deadlineSupported := !hasDeadline
	if hasDeadline {
		deadlineSupported = pc.SetDeadline(deadline) == nil
	}
	if _, err = pc.WriteTo(req, dst); err != nil {
		return false
	}
	buf := make([]byte, 512)
	readPacket := func() (int, net.Addr, error) {
		if deadlineSupported {
			return pc.ReadFrom(buf)
		}
		// A few Android PacketConn implementations reject SetDeadline. Keep
		// the read cancellable by closing the connection on context expiry;
		// the buffered result channel lets the reader exit without leaking a
		// goroutine after this function returns.
		type packetResult struct {
			n   int
			src net.Addr
			err error
		}
		result := make(chan packetResult, 1)
		go func() {
			n, src, readErr := pc.ReadFrom(buf)
			result <- packetResult{n: n, src: src, err: readErr}
		}()
		select {
		case value := <-result:
			return value.n, value.src, value.err
		case <-ctx.Done():
			_ = pc.Close()
			return 0, nil, ctx.Err()
		}
	}
	for {
		n, src, err := readPacket()
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

// CapabilityDemoted reports whether a probe has CONFIRMED that this proxy
// lacks a preferred capability. An unfinished probe is not a demotion: treating
// unknown like a confirmed failure would penalize every node that simply has
// not been measured yet, which on a large provider means the whole group is
// demoted for the first minutes after a config load.
func CapabilityDemoted(p C.Proxy, preferUDP, preferIPv6 bool) bool {
	if p == nil || (!preferUDP && !preferIPv6) {
		return false
	}
	state := capabilityStateForProxy(p)
	if preferUDP && state.stateOrProbe(p, capabilityUDP) == capNo {
		return true
	}
	return preferIPv6 && state.stateOrProbe(p, capabilityIPv6) == capNo
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
