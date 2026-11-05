//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tailscale/client/tailscale/apitype"
	"github.com/metacubex/tailscale/tsnet"
)

// TailscaleServeOption publishes a local HTTP service on this node's own
// Tailscale addresses, like `tailscale serve`. Requests are reverse-proxied to
// target and carry the caller's Tailscale identity (Tailscale-User-Login,
// Tailscale-User-Name); headers of that name sent by the client are dropped.
//
// target is either http://IP:PORT or unix:PATH (relative to the home
// directory). A unix socket inside the home directory is reachable only by
// processes that may read that directory, so the identity headers can be
// trusted there; a loopback TCP target is reachable by every local process.
type TailscaleServeOption struct {
	Port   uint16 `proxy:"port"`
	Target string `proxy:"target"`
}

type tailscaleServeTarget struct {
	port    uint16
	network string // "tcp" or "unix"
	address string
	origin  *url.URL
}

const tailscaleServeWhoIsTimeout = 5 * time.Second

func parseTailscaleServe(options []TailscaleServeOption) ([]tailscaleServeTarget, error) {
	targets := make([]tailscaleServeTarget, 0, len(options))
	seen := make(map[uint16]bool, len(options))
	for _, option := range options {
		if option.Port == 0 {
			return nil, errors.New("serve: port is required")
		}
		if seen[option.Port] {
			return nil, fmt.Errorf("serve: duplicate port %d", option.Port)
		}
		seen[option.Port] = true
		target := tailscaleServeTarget{port: option.Port}
		raw := strings.TrimSpace(option.Target)
		switch {
		case strings.HasPrefix(raw, "unix:"):
			path := strings.TrimPrefix(strings.TrimPrefix(raw, "unix:"), "//")
			if path == "" {
				return nil, fmt.Errorf("serve %d: empty unix socket path", option.Port)
			}
			path = C.Path.Resolve(path)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
			target.network, target.address = "unix", path
			target.origin = &url.URL{Scheme: "http", Host: "tailscale-serve"}
		case strings.HasPrefix(raw, "http://"):
			parsed, err := url.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("serve %d: invalid target: %w", option.Port, err)
			}
			if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
				return nil, fmt.Errorf("serve %d: target must be http://IP:PORT", option.Port)
			}
			// An IP literal keeps the dial away from DNS (and from mihomo's own resolver).
			addrPort, err := netip.ParseAddrPort(parsed.Host)
			if err != nil {
				return nil, fmt.Errorf("serve %d: target must be http://IP:PORT: %w", option.Port, err)
			}
			target.network, target.address = "tcp", addrPort.String()
			target.origin = &url.URL{Scheme: "http", Host: addrPort.String()}
		default:
			return nil, fmt.Errorf("serve %d: target must be http://IP:PORT or unix:PATH", option.Port)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

// tailscaleHeaderValue encodes non-ASCII values the same way tailscale serve
// does, so header consumers can share one decoder.
func tailscaleHeaderValue(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf || value[i] < 0x20 {
			return mime.QEncoding.Encode("utf-8", value)
		}
	}
	return value
}

type tailscaleWhoIsKey struct{}

func tailscaleServeHandler(target tailscaleServeTarget, whois func(context.Context, string) (*apitype.WhoIsResponse, error)) http.Handler {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target.origin)
			request.Out.Host = request.In.Host
			request.SetXForwarded()
			for name := range request.Out.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(name), "Tailscale-") {
					request.Out.Header.Del(name)
				}
			}
			who, _ := request.In.Context().Value(tailscaleWhoIsKey{}).(*apitype.WhoIsResponse)
			if who == nil || who.Node == nil || who.UserProfile == nil || who.Node.IsTagged() {
				return
			}
			request.Out.Header.Set("Tailscale-User-Login", tailscaleHeaderValue(who.UserProfile.LoginName))
			request.Out.Header.Set("Tailscale-User-Name", tailscaleHeaderValue(who.UserProfile.DisplayName))
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, target.network, target.address)
			},
			MaxIdleConns:          8,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
		},
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
			log.Debugln("[Tailscale] serve %d: %v", target.port, err)
			http.Error(writer, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), tailscaleServeWhoIsTimeout)
		who, err := whois(ctx, request.RemoteAddr)
		cancel()
		if err != nil {
			// Unknown callers are forwarded without identity; the target decides.
			log.Debugln("[Tailscale] serve %d: whois %s: %v", target.port, request.RemoteAddr, err)
			who = nil
		}
		proxy.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), tailscaleWhoIsKey{}, who)))
	})
}

// startServeLocked publishes the serve targets on a freshly started server.
// Failures are logged: the outbound itself keeps working without them.
func (t *Tailscale) startServeLocked(server *tsnet.Server) {
	if len(t.serveTargets) == 0 || server == nil {
		return
	}
	client, err := server.LocalClient()
	if err != nil {
		log.Warnln("[Tailscale](%s) serve disabled: %v", t.option.Name, err)
		return
	}
	for _, target := range t.serveTargets {
		listener, err := server.Listen("tcp", fmt.Sprintf(":%d", target.port))
		if err != nil {
			log.Warnln("[Tailscale](%s) serve %d: %v", t.option.Name, target.port, err)
			continue
		}
		httpServer := &http.Server{
			Handler:           tailscaleServeHandler(target, client.WhoIs),
			ReadHeaderTimeout: 30 * time.Second,
		}
		t.serveServers = append(t.serveServers, httpServer)
		go func(target tailscaleServeTarget) {
			if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warnln("[Tailscale](%s) serve %d stopped: %v", t.option.Name, target.port, err)
			}
		}(target)
		log.Infoln("[Tailscale](%s) serving port %d -> %s:%s", t.option.Name, target.port, target.network, target.address)
	}
}

func (t *Tailscale) closeServeLocked() {
	for _, server := range t.serveServers {
		_ = server.Close()
	}
	t.serveServers = nil
}
