package route

import (
	"context"
	"sort"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// tailscaleControl is implemented by the tailscale outbound when it is built
// in; matching by interface keeps this router free of build tags.
type tailscaleControl interface {
	TailscaleStatus(ctx context.Context) map[string]any
	TailscaleLogin(ctx context.Context, wait time.Duration) (map[string]any, error)
	TailscaleLogout(ctx context.Context) error
}

func tailscaleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", listTailscale)
	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName)
		r.Get("/", getTailscale)
		r.Post("/login", loginTailscale)
		r.Post("/logout", logoutTailscale)
	})
	return r
}

func tailscaleOutbounds() map[string]tailscaleControl {
	out := map[string]tailscaleControl{}
	for name, proxy := range tunnel.Proxies() {
		if proxy.Type() != C.Tailscale {
			continue
		}
		if control, ok := proxy.Adapter().(tailscaleControl); ok {
			out[name] = control
		}
	}
	return out
}

func findTailscale(w http.ResponseWriter, r *http.Request) (tailscaleControl, bool) {
	name := r.Context().Value(CtxKeyProxyName).(string)
	control, ok := tailscaleOutbounds()[name]
	if !ok {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
	return control, ok
}

func listTailscale(w http.ResponseWriter, r *http.Request) {
	outbounds := tailscaleOutbounds()
	names := make([]string, 0, len(outbounds))
	for name := range outbounds {
		names = append(names, name)
	}
	sort.Strings(names)
	list := make([]map[string]any, 0, len(names))
	for _, name := range names {
		list = append(list, outbounds[name].TailscaleStatus(r.Context()))
	}
	render.JSON(w, r, render.M{"tailscale": list})
}

func getTailscale(w http.ResponseWriter, r *http.Request) {
	control, ok := findTailscale(w, r)
	if !ok {
		return
	}
	render.JSON(w, r, control.TailscaleStatus(r.Context()))
}

// loginTailscale starts the backend and waits (?wait=seconds, default 20, at
// most 60) for it to run or to hand out an interactive login URL.
func loginTailscale(w http.ResponseWriter, r *http.Request) {
	control, ok := findTailscale(w, r)
	if !ok {
		return
	}
	wait := 20
	if text := r.URL.Query().Get("wait"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 1 || value > 60 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		wait = value
	}
	status, err := control.TailscaleLogin(r.Context(), time.Duration(wait)*time.Second)
	if err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.JSON(w, r, status)
}

func logoutTailscale(w http.ResponseWriter, r *http.Request) {
	control, ok := findTailscale(w, r)
	if !ok {
		return
	}
	if err := control.TailscaleLogout(r.Context()); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}
