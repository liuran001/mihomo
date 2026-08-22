//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	ts "github.com/metacubex/tailscale"
	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/hostinfo"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/net/tsaddr"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

const (
	tailscaleExitNodeRetryDelay    = 2 * time.Second
	tailscaleExitNodeRetryMaxDelay = 30 * time.Second
)

var errTailscaleBackendNotRunning = errors.New("tailscale backend is not running")

type Tailscale struct {
	*Base
	server      *tsnet.Server
	dnsResolver *dns.Resolver
	option      TailscaleOption
	ctx         context.Context
	cancel      context.CancelFunc
	startOnce   sync.Once
	startErr    error

	backendInitOnce sync.Once
	backendInitCh   chan struct{}
	backendInitErr  error
	backendReady    atomic.Bool

	backendStateAccess     sync.Mutex
	backendState           ipn.State
	backendGeneration      uint64
	backendRetrying        bool
	backendRetryCancel     context.CancelFunc
	backendStateErr        error
	applyExitNodePrefsHook func(context.Context) error
	backendIsRunningHook   func(context.Context) (bool, error)

	serverStarted    atomic.Bool
	advertisedRoutes []netip.Prefix
	udpFlows         chan struct{}

	unregisterDNSResolver func()
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	ListenPort uint16 `proxy:"listen-port,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool    `proxy:"accept-routes,omitempty"`
	ExitNode               string   `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool    `proxy:"exit-node-allow-lan-access,omitempty"`
	AdvertiseRoutes        []string `proxy:"advertise-routes,omitempty"`
	AdvertiseExitNode      bool     `proxy:"advertise-exit-node,omitempty"`
}

// parseAdvertiseRoutes builds the AdvertiseRoutes prefix list from the
// advertise-routes and advertise-exit-node options. It returns nil when
// neither is configured.
func parseAdvertiseRoutes(option TailscaleOption) ([]netip.Prefix, error) {
	if len(option.AdvertiseRoutes) == 0 && !option.AdvertiseExitNode {
		return nil, nil
	}
	routes := make([]netip.Prefix, 0, len(option.AdvertiseRoutes)+2)
	for _, route := range option.AdvertiseRoutes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil {
			return nil, fmt.Errorf("invalid advertise-routes entry %q: %w", route, err)
		}
		routes = append(routes, prefix.Masked())
	}
	if option.AdvertiseExitNode {
		routes = append(routes, tsaddr.AllIPv4(), tsaddr.AllIPv6())
	}
	return routes, nil
}

func init() {
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		versionDotTxt := strings.TrimSpace(ts.VersionDotTxt)
		hi.IPNVersion = fmt.Sprintf("%s-%s-%s", versionDotTxt, C.MihomoName, C.Version)
	})
	envknob.SetNoLogsNoSupport()
	if runtime.GOOS == "android" { // Android SDK 30 no longer permits Go's net.Interfaces to work (Issue 2293)
		netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
			log.Debugln("[Tailscale] InterfaceGetter: start, IsForceAnet: %v", anet.IsForceAnet())
			ifaces, err := anet.Interfaces()
			if err != nil {
				log.Warnln("[Tailscale] anet.Interfaces failed: %v", err)
				return nil, err
			}
			for _, iff := range ifaces {
				addrs, err := anet.InterfaceAddrsByInterface(&iff)
				if err != nil {
					log.Warnln("[Tailscale] anet.InterfaceAddrsByInterface(%v) failed: %v", iff.Name, err)
					continue
				}
				nif = append(nif, netmon.Interface{
					Interface: &net.Interface{
						Index:        iff.Index,
						MTU:          iff.MTU,
						Name:         iff.Name,
						HardwareAddr: iff.HardwareAddr,
						Flags:        iff.Flags,
					},
					AltAddrs: addrs,
				})
			}

			log.Debugln("[Tailscale] InterfaceGetter: %v", lo.Map(nif, func(item netmon.Interface, index int) string {
				var addrs any
				addrs, err := item.Addrs()
				if err != nil {
					addrs = err
				}
				return fmt.Sprintf("{Name: %s, Addrs: %v, IsUp: %v, IsLoopback: %v}", item.Name, addrs, item.IsUp(), item.IsLoopback())
			}))
			return
		})
	}
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	advertisedRoutes, err := parseAdvertiseRoutes(option)
	if err != nil {
		return nil, err
	}
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:           option,
		ctx:              ctx,
		cancel:           cancel,
		backendInitCh:    make(chan struct{}),
		advertisedRoutes: advertisedRoutes,
		udpFlows:         make(chan struct{}, 1024),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.server = &tsnet.Server{
		Dir:        option.StateDir,
		Hostname:   option.Hostname,
		Port:       option.ListenPort,
		AuthKey:    option.AuthKey,
		ControlURL: option.ControlURL,
		Ephemeral:  option.Ephemeral,
		SystemDialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Debugln("[Tailscale](%s) SystemDialer: start dial %s %s", option.Name, network, address)
			conn, err := outbound.dialer.DialContext(ctx, network, address)
			log.Debugln("[Tailscale](%s) SystemDialer: finish dial %s %s, err: %v", option.Name, network, address, err)
			return conn, err
		},
		SystemPacketListener: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			log.Debugln("[Tailscale](%s) SystemPacketListener: start listen %s %s", option.Name, network, address)
			var pc net.PacketConn
			var err error
			if option.Interface == "" && dialer.DefaultSocketHook == nil {
				// Leave the magicsock UDP socket unbound: binding it to the
				// auto-detected default interface (or the TUN interface finder
				// fallback) prevents it from receiving packets from peers on
				// other local interfaces (e.g. LAN), forcing DERP relay even
				// for directly reachable peers.
				//
				// An unbound socket's egress can however be captured by
				// mihomo's own TUN when auto-route is active (its policy rules
				// send local-originated traffic with an undecided source into
				// the TUN table), looping magicsock traffic back through
				// mihomo. Honor the proxy's routing-mark (or the global one)
				// so users can route the socket around the TUN; alternatively
				// set listen-port and exclude it via tun.exclude-src-port.
				mark := option.RoutingMark
				if mark == 0 {
					mark = int(dialer.DefaultRoutingMark.Load())
				}
				lc := &net.ListenConfig{}
				if mark != 0 {
					dialer.BindMarkToListenConfig(mark, lc, network, address)
				}
				pc, err = lc.ListenPacket(ctx, network, address)
			} else {
				pc, err = outbound.dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
			}
			log.Debugln("[Tailscale](%s) SystemPacketListener: finish listen %s %s, err: %v", option.Name, network, address, err)
			return pc, err
		},
		ExtraRootCAs: ca.GetCertPool(),
		LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
			log.Debugln("[Tailscale](%s) LookupHook: start lookup %s", option.Name, host)
			ips, err := resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
			log.Debugln("[Tailscale](%s) LookupHook: finish lookup %s, ips: %v, err: %v", option.Name, host, ips, err)
			return ips, err
		},
		UserLogf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			log.Debugln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
	}
	dnsTransport := tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(dnsTransport)
	outbound.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(option.Name, dnsTransport)
	if len(advertisedRoutes) > 0 {
		if tunnel := option.NewTunnel(); tunnel != nil {
			outbound.registerInboundHandlers(tunnel)
		} else {
			log.Warnln("[Tailscale](%s) advertise-routes configured but no tunnel available; inbound flows will be rejected", option.Name)
		}
		// Advertised routes mean this node serves the tailnet (subnet router
		// or exit node), so bring the backend up eagerly instead of waiting
		// for the first locally-routed connection: peers must be able to
		// reach it right after a (re)start, and DNS "ts://" lookups would
		// otherwise fail during the lazy-start window.
		go func() {
			if err := outbound.start(); err != nil {
				log.Warnln("[Tailscale](%s) eager start failed: %v", option.Name, err)
			}
		}()
	}
	return outbound, nil
}

func (t *Tailscale) start() error {
	t.startOnce.Do(func() {
		if err := t.server.Start(); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		t.serverStarted.Store(true)
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if err := t.applyPrefs(ctx); err != nil {
			t.startErr = err
			t.setBackendInitialized(err)
			return
		}
		go t.watchBackendState()
	})
	return t.startErr
}

func (t *Tailscale) ensureStarted(ctx context.Context) error {
	if err := t.start(); err != nil {
		return err
	}
	if err := t.waitBackendInitialized(ctx); err != nil {
		return err
	}
	if !t.backendReady.Load() {
		if err := t.currentBackendStateError(); err != nil {
			return err
		}
		return errTailscaleBackendNotRunning
	}
	return nil
}

func (t *Tailscale) watchBackendState() {
	lc, err := t.server.LocalClient()
	if err != nil {
		t.markBackendUnavailable(err)
		t.setBackendInitialized(err)
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialState)
	if err != nil {
		t.markBackendUnavailable(err)
		t.setBackendInitialized(err)
		return
	}
	defer watcher.Close()

	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(t.option)
	for {
		n, err := watcher.Next()
		if err != nil {
			t.markBackendUnavailable(err)
			t.setBackendInitialized(err)
			return
		}
		if n.ErrMessage != nil {
			err := errors.New("tailscale backend: " + *n.ErrMessage)
			t.markBackendUnavailable(err)
			// Keep the initialization gate open until the watcher either
			// observes a valid Running state or terminates. ErrMessage can be
			// transient; closing the once-only gate here would make a later
			// recovery impossible.
			continue
		}
		if n.State == nil {
			continue
		}
		t.observeBackendState(*n.State, exitNodeNeedsStatus)
	}
}

// observeBackendState consumes an IPN state notification without blocking the
// watcher. Exit-node preference application runs in a cancellable goroutine
// tied to the current Running generation, so a stale success cannot revive a
// backend that has already left Running.
func (t *Tailscale) observeBackendState(state ipn.State, exitNodeNeedsStatus bool) {
	t.backendStateAccess.Lock()
	if state != t.backendState {
		t.backendState = state
		t.backendGeneration++
		t.backendStateErr = nil
	}
	generation := t.backendGeneration
	if !tailscaleBackendReady(state) {
		t.backendReady.Store(false)
		if t.backendRetryCancel != nil {
			t.backendRetryCancel()
			t.backendRetryCancel = nil
		}
		t.backendRetrying = false
		t.backendStateAccess.Unlock()
		return
	}
	if t.backendReady.Load() || t.backendRetrying {
		t.backendStateAccess.Unlock()
		return
	}
	if !exitNodeNeedsStatus {
		t.backendReady.Store(true)
		t.backendStateAccess.Unlock()
		t.setBackendInitialized(nil)
		return
	}
	retryCtx, retryCancel := context.WithCancel(t.ctx)
	t.backendRetrying = true
	t.backendRetryCancel = retryCancel
	t.backendStateAccess.Unlock()
	go t.retryExitNodePrefs(retryCtx, generation)
}

func (t *Tailscale) retryExitNodePrefs(ctx context.Context, generation uint64) {
	err := t.applyExitNodePrefsUntilReady(ctx)
	t.backendStateAccess.Lock()
	defer t.backendStateAccess.Unlock()
	if generation != t.backendGeneration || t.backendState != ipn.Running || ctx.Err() != nil {
		if generation == t.backendGeneration {
			t.backendRetrying = false
			t.backendRetryCancel = nil
		}
		return
	}
	t.backendRetrying = false
	t.backendRetryCancel = nil
	if err != nil {
		t.backendStateErr = err
		t.backendReady.Store(false)
		return
	}
	t.backendStateErr = nil
	t.backendReady.Store(true)
	t.setBackendInitialized(nil)
}

func (t *Tailscale) markBackendUnavailable(err error) {
	t.backendStateAccess.Lock()
	t.backendGeneration++
	t.backendState = ipn.NoState
	t.backendStateErr = err
	t.backendReady.Store(false)
	if t.backendRetryCancel != nil {
		t.backendRetryCancel()
		t.backendRetryCancel = nil
	}
	t.backendRetrying = false
	t.backendStateAccess.Unlock()
}

func (t *Tailscale) currentBackendStateError() error {
	t.backendStateAccess.Lock()
	defer t.backendStateAccess.Unlock()
	return t.backendStateErr
}

func (t *Tailscale) applyExitNodePrefsUntilReady(ctx context.Context) error {
	delay := tailscaleExitNodeRetryDelay
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		applyPrefs := t.applyExitNodePrefs
		if t.applyExitNodePrefsHook != nil {
			applyPrefs = t.applyExitNodePrefsHook
		}
		if err := applyPrefs(ctx); err == nil {
			checkRunning := t.backendStatusRunning
			if t.backendIsRunningHook != nil {
				checkRunning = t.backendIsRunningHook
			}
			running, statusErr := checkRunning(ctx)
			if statusErr == nil && running {
				return nil
			}
			if statusErr != nil {
				log.Warnln("[Tailscale](%s) verify running state failed, retrying: %v", t.Name(), statusErr)
			} else {
				log.Warnln("[Tailscale](%s) backend left Running while applying exit node, retrying", t.Name())
			}
		} else {
			log.Warnln("[Tailscale](%s) set exit node failed, retrying: %v", t.Name(), err)
		}

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		}
		if delay < tailscaleExitNodeRetryMaxDelay {
			delay *= 2
			if delay > tailscaleExitNodeRetryMaxDelay {
				delay = tailscaleExitNodeRetryMaxDelay
			}
		}
	}
}

func (t *Tailscale) backendStatusRunning(ctx context.Context) (bool, error) {
	lc, err := t.server.LocalClient()
	if err != nil {
		return false, err
	}
	status, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return false, err
	}
	state, ok := ipn.StateFromString(status.BackendState)
	return ok && state == ipn.Running, nil
}

func tailscaleBackendReady(state ipn.State) bool {
	return state == ipn.Running
}

func (t *Tailscale) setBackendInitialized(err error) {
	t.backendInitOnce.Do(func() {
		t.backendInitErr = err
		close(t.backendInitCh)
	})
}

func (t *Tailscale) waitBackendInitialized(ctx context.Context) error {
	select {
	case <-t.backendInitCh:
		return t.backendInitErr
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Tailscale) applyPrefs(ctx context.Context) error {
	mp, err := buildTailscaleMaskedPrefs(t.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (t *Tailscale) applyExitNodePrefs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := t.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if t.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *t.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(t.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	advertiseRoutes, err := parseAdvertiseRoutes(option)
	if err != nil {
		return nil, err
	}
	if advertiseRoutes != nil {
		mp.AdvertiseRoutes = advertiseRoutes
		mp.AdvertiseRoutesSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	netStack, err := t.server.Netstack(ctx)
	if err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	options := t.DialOptions()
	options = append(options, dialer.WithResolver(t.dnsResolver))
	options = append(options, dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
		if err != nil {
			return nil, err
		}
		src := v4
		if dst.Addr().Is6() {
			src = v6
		}
		tcpConn, err := netStack.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	})))
	var conn net.Conn
	conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	v4, v6 := t.server.TailscaleIPs()
	src := v4
	if metadata.DstIP.Is6() {
		src = v6
	}
	pc, err := t.server.ListenPacket("udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, t.prefer, t.dnsResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.tailscale.ensureStarted(ctx); err != nil {
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	lc, err := t.tailscale.server.LocalClient()
	if err != nil {
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (t *Tailscale) Close() error {
	t.cancel()
	t.markBackendUnavailable(errors.New("tailscale outbound closed"))
	if t.unregisterDNSResolver != nil {
		t.unregisterDNSResolver()
	}
	t.startOnce.Do(func() {
		t.startErr = errors.New("tailscale outbound closed")
	})
	if t.server != nil && t.serverStarted.Load() { // tsnet.Server.Close() must not be called before or concurrently with Start.
		return t.server.Close()
	}
	return nil
}
