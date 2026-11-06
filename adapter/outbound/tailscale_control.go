//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
)

type tailscaleControlSnapshot struct {
	state          ipn.State
	stateError     error
	authURL        string
	health         []string
	self           *tailscaleControlSelf
	profile        tailcfg.UserProfile
	tailnet        string
	magicDNSSuffix string
}

type tailscaleControlSelf struct {
	userID   tailcfg.UserID
	hostName string
	dnsName  string
	ips      []string
	online   *bool
}

func (t *Tailscale) resetControlStatus() {
	t.controlAccess.Lock()
	t.controlStatus = tailscaleControlSnapshot{}
	t.controlAccess.Unlock()
}

func (t *Tailscale) observeControlNotify(notification ipn.Notify) {
	t.controlAccess.Lock()
	defer t.controlAccess.Unlock()
	status := &t.controlStatus
	if notification.State != nil {
		if status.state != *notification.State {
			status.stateError = nil
		}
		status.state = *notification.State
		if status.state == ipn.NeedsLogin {
			status.self = nil
			status.profile = tailcfg.UserProfile{}
			status.tailnet = ""
			status.magicDNSSuffix = ""
		}
		if status.state == ipn.Running {
			status.authURL = ""
		}
	}
	if notification.ErrMessage != nil {
		status.stateError = errors.New(*notification.ErrMessage)
	}
	if notification.BrowseToURL != nil && status.state != ipn.Running {
		status.authURL = *notification.BrowseToURL
	}
	if notification.Prefs != nil && notification.Prefs.Valid() && notification.Prefs.Persist().Valid() {
		if profile := notification.Prefs.Persist().UserProfile(); profile.Valid() {
			status.profile = *profile.AsStruct()
		}
	}
	self := notification.SelfChange
	if network := notification.NetMap; network != nil {
		status.tailnet = network.Domain
		status.magicDNSSuffix = network.MagicDNSSuffix()
		if network.SelfNode.Valid() {
			self = network.SelfNode.AsStruct()
			status.profile = tailcfg.UserProfile{}
			if profile, ok := network.UserProfiles[self.User]; ok && profile.Valid() {
				status.profile = *profile.AsStruct()
			}
		}
	}
	if self != nil {
		identity := &tailscaleControlSelf{userID: self.User, dnsName: self.Name}
		if self.Hostinfo.Valid() {
			identity.hostName = self.Hostinfo.Hostname()
		}
		for _, address := range self.Addresses {
			if address.IsSingleIP() {
				identity.ips = append(identity.ips, address.Addr().String())
			}
		}
		if self.Online != nil {
			online := *self.Online
			identity.online = &online
		}
		_, suffix, _ := strings.Cut(strings.TrimSuffix(self.Name, "."), ".")
		if status.magicDNSSuffix != suffix {
			status.tailnet = ""
		}
		status.magicDNSSuffix = suffix
		status.self = identity
		if status.profile.ID != self.User {
			status.profile = tailcfg.UserProfile{}
		}
	}
	if notification.Health != nil {
		status.health = make([]string, 0, len(notification.Health.Warnings))
		for _, warning := range notification.Health.Warnings {
			status.health = append(status.health, warning.Text)
		}
		slices.Sort(status.health)
	}
}

// TailscaleStatus reports the login and connection state of this outbound for
// the external controller. It never starts the backend.
func (t *Tailscale) TailscaleStatus(ctx context.Context) map[string]any {
	t.controlAccess.Lock()
	status := t.controlStatus
	t.controlAccess.Unlock()

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
		out["state"] = status.state.String()
	} else {
		out["state"] = "NotStarted"
	}
	if err := t.startErr.Load(); err != nil {
		out["error"] = err.Error()
	} else if status.stateError != nil {
		out["error"] = status.stateError.Error()
	}
	if routes := t.advertisedRoutes; len(routes) > 0 {
		list := make([]string, 0, len(routes))
		for _, prefix := range routes {
			list = append(list, prefix.String())
		}
		out["advertiseRoutes"] = list
	}
	if status.authURL != "" {
		out["authURL"] = status.authURL
	}
	if len(status.health) > 0 {
		out["health"] = slices.Clone(status.health)
	}
	if status.tailnet != "" {
		out["tailnet"] = status.tailnet
	}
	if status.magicDNSSuffix != "" {
		out["magicDNSSuffix"] = status.magicDNSSuffix
	}
	if self := status.self; self != nil && started {
		identity := map[string]any{
			"hostName": self.hostName,
			"dnsName":  self.dnsName,
			"ips":      slices.Clone(self.ips),
		}
		if self.online != nil {
			identity["online"] = *self.online
		}
		out["self"] = identity
		if status.profile.ID == self.userID && status.profile.LoginName != "" {
			out["login"] = status.profile.LoginName
			out["displayName"] = status.profile.DisplayName
		}
	}
	return out
}

// TailscaleLogin starts the backend if needed and waits up to wait for either
// a running backend or an interactive login URL. With an auth key the backend
// logs in by itself; interactive login is only requested when the backend
// still needs login after a short grace period (or immediately without a key).
func (t *Tailscale) TailscaleLogin(ctx context.Context, wait time.Duration) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := t.startContext(ctx); err != nil {
		return nil, err
	}
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
			if server, err := t.controlServer(); err == nil {
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
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	server, err := t.controlServer()
	if err != nil {
		return err
	}
	lc, err := server.LocalClient()
	if err != nil {
		return err
	}
	return lc.Logout(ctx)
}

func (t *Tailscale) controlServer() (*tsnet.Server, error) {
	if !t.startAccess.TryLock() {
		return nil, errors.New("tailscale startup or shutdown is in progress")
	}
	defer t.startAccess.Unlock()
	if t.closed || !t.serverStarted.Load() || t.server == nil {
		return nil, errTailscaleBackendNotRunning
	}
	return t.server, nil
}

func (t *Tailscale) serveSummary() []map[string]any {
	list := make([]map[string]any, 0, len(t.option.Serve))
	for _, s := range t.option.Serve {
		list = append(list, map[string]any{"port": s.Port, "target": s.Target})
	}
	return list
}
