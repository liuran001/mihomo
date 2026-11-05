//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"time"

	"github.com/metacubex/tailscale/ipn"
)

// TailscaleStatus reports the login and connection state of this outbound for
// the external controller. It never starts the backend.
func (t *Tailscale) TailscaleStatus(ctx context.Context) map[string]any {
	t.startAccess.Lock()
	startErr := t.startErr
	t.startAccess.Unlock()
	t.backendStateAccess.Lock()
	state := t.backendState
	stateErr := t.backendStateErr
	t.backendStateAccess.Unlock()

	started := t.serverStarted.Load()
	out := map[string]any{
		"name":      t.Name(),
		"started":   started,
		"ready":     t.backendReady.Load(),
		"hostname":  t.option.Hostname,
		"authKey":   t.option.AuthKey != "",
		"ephemeral": t.option.Ephemeral,
		"serve":     t.serveSummary(),
	}
	if started {
		out["state"] = state.String()
	} else {
		out["state"] = "NotStarted"
	}
	if err := startErr; err != nil {
		out["error"] = err.Error()
	} else if stateErr != nil {
		out["error"] = stateErr.Error()
	}
	if routes := t.advertisedRoutes; len(routes) > 0 {
		list := make([]string, 0, len(routes))
		for _, prefix := range routes {
			list = append(list, prefix.String())
		}
		out["advertiseRoutes"] = list
	}
	server, err := t.snapshotServer()
	if err != nil {
		return out
	}
	lc, err := server.LocalClient()
	if err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["state"] = st.BackendState
	if st.AuthURL != "" {
		out["authURL"] = st.AuthURL
	}
	if len(st.Health) > 0 {
		out["health"] = st.Health
	}
	if st.CurrentTailnet != nil {
		out["tailnet"] = st.CurrentTailnet.Name
		out["magicDNSSuffix"] = st.CurrentTailnet.MagicDNSSuffix
	}
	if self := st.Self; self != nil {
		ips := make([]string, 0, len(self.TailscaleIPs))
		for _, ip := range self.TailscaleIPs {
			ips = append(ips, ip.String())
		}
		out["self"] = map[string]any{
			"hostName": self.HostName,
			"dnsName":  self.DNSName,
			"ips":      ips,
			"online":   self.Online,
		}
		if user, ok := st.User[self.UserID]; ok {
			out["login"] = user.LoginName
			out["displayName"] = user.DisplayName
		}
	}
	return out
}

// TailscaleLogin starts the backend if needed and waits up to wait for either
// a running backend or an interactive login URL. With an auth key the backend
// logs in by itself; interactive login is only requested when the backend
// still needs login after a short grace period (or immediately without a key).
func (t *Tailscale) TailscaleLogin(ctx context.Context, wait time.Duration) (map[string]any, error) {
	if err := t.start(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	begin := time.Now()
	grace := 4 * time.Second
	if t.option.AuthKey == "" {
		grace = 0
	}
	interactive := false
	for {
		status := t.TailscaleStatus(ctx)
		state, _ := status["state"].(string)
		if state == ipn.Running.String() {
			return status, nil
		}
		if url, _ := status["authURL"].(string); url != "" {
			return status, nil
		}
		if !interactive && state == ipn.NeedsLogin.String() && time.Since(begin) >= grace {
			if server, err := t.snapshotServer(); err == nil {
				if lc, err := server.LocalClient(); err == nil {
					if err := lc.StartLoginInteractive(ctx); err == nil {
						interactive = true
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return t.TailscaleStatus(context.Background()), nil
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// TailscaleLogout logs the node out of its tailnet. The backend keeps running
// in NeedsLogin state so a later login can reuse the same server.
func (t *Tailscale) TailscaleLogout(ctx context.Context) error {
	server, err := t.snapshotServer()
	if err != nil {
		return err
	}
	lc, err := server.LocalClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return lc.Logout(ctx)
}

func (t *Tailscale) serveSummary() []map[string]any {
	list := make([]map[string]any, 0, len(t.option.Serve))
	for _, s := range t.option.Serve {
		list = append(list, map[string]any{"port": s.Port, "target": s.Target})
	}
	return list
}
