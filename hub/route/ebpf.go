//go:build with_ebpf && (linux || android)

package route

import (
	"sync"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/listener/sing_ebpf"
)

var ebpfInspectionAccess sync.Mutex

func addEBPFRoutes(r chi.Router) {
	r.Get("/ebpf", func(w http.ResponseWriter, r *http.Request) {
		if !ebpfInspectionAccess.TryLock() {
			render.Status(r, http.StatusTooManyRequests)
			render.JSON(w, r, newError("eBPF inspection is already in progress"))
			return
		}
		defer ebpfInspectionAccess.Unlock()
		render.JSON(w, r, map[string]any{"inbounds": sing_ebpf.DiagnosticsContext(r.Context())})
	})
	r.Get("/ebpf/summary", func(writer http.ResponseWriter, request *http.Request) {
		render.JSON(writer, request, map[string]any{"inbounds": sing_ebpf.DiagnosticsSummary()})
	})
}
