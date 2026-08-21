package adapter

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
// globally by proxy name with a TTL; unknown nodes stay selectable until a
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
	capabilityCache sync.Map // proxy name -> *capabilityState
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

// passesOrProbe reports whether the proxy currently passes the capability
// requirement. Unknown or expired entries schedule an async probe and pass.
func (s *capabilityState) passesOrProbe(p C.Proxy, kind capabilityKind) bool {
	entry := &s.udp
	if kind == capabilityIPv6 {
		entry = &s.ipv6
	}
	entry.mu.Lock()
	if entry.known && time.Now().Before(entry.expire) {
		ok := entry.ok
		entry.mu.Unlock()
		return ok
	}
	stale := entry.known
	staleOK := entry.ok
	if !entry.probing {
		entry.probing = true
		go probeCapability(p, kind, entry)
	}
	entry.mu.Unlock()
	if stale {
		return staleOK // keep last verdict while re-probing
	}
	return true // unknown: stay selectable until proven missing
}

func probeCapability(p C.Proxy, kind capabilityKind, entry *capabilityEntry) {
	capabilityProbeSem <- struct{}{}
	defer func() { <-capabilityProbeSem }()

	ctx, cancel := context.WithTimeout(context.Background(), capabilityProbeTimeout)
	defer cancel()

	var ok bool
	switch kind {
	case capabilityUDP:
		ok = probeUDP(ctx, p)
	case capabilityIPv6:
		_, err := p.URLTest(ctx, capabilityIPv6URL, nil)
		ok = err == nil
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
	_, _ = rand.Read(req[8:20])

	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), port))
	deadline, _ := ctx.Deadline()
	_ = pc.SetDeadline(deadline)
	if _, err = pc.WriteTo(req, dst); err != nil {
		return false
	}
	buf := make([]byte, 512)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return false
		}
		if n >= 20 && binary.BigEndian.Uint32(buf[4:8]) == 0x2112A442 {
			return true
		}
	}
}

// FilterProxiesByCapability drops proxies whose probed capabilities are known
// to miss the requirements. Unknown nodes pass (and get probed). If every
// proxy would be dropped the original list is returned so the group never
// goes empty because of probing.
func FilterProxiesByCapability(proxies []C.Proxy, requireUDP, requireIPv6 bool) []C.Proxy {
	if !requireUDP && !requireIPv6 {
		return proxies
	}
	filtered := make([]C.Proxy, 0, len(proxies))
	for _, p := range proxies {
		state := capabilityStateFor(p.Name())
		if requireUDP && !state.passesOrProbe(p, capabilityUDP) {
			continue
		}
		if requireIPv6 && !state.passesOrProbe(p, capabilityIPv6) {
			continue
		}
		filtered = append(filtered, p)
	}
	if len(filtered) == 0 {
		log.Warnln("[Capability] all proxies filtered out by capability requirements, keeping original list")
		return proxies
	}
	return filtered
}
