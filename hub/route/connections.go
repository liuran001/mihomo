package route

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func connectionRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConnections)
	r.Get("/summary", getConnectionSummary)
	r.Get("/sources", getConnectionSources)
	r.Delete("/", closeAllConnections)
	r.Delete("/{id}", closeConnection)
	r.Delete("/smart/{id}", setSmartBlock)
	return r
}

func getConnectionSummary(writer http.ResponseWriter, request *http.Request) {
	render.JSON(writer, request, statistic.DefaultManager.Summary())
}

// getConnectionSources reports traffic per source address since start, so a
// dashboard can show per-device totals and derive rates between polls.
func getConnectionSources(writer http.ResponseWriter, request *http.Request) {
	render.JSON(writer, request, render.M{"sources": statistic.DefaultManager.SourceTraffic()})
}

func getConnections(w http.ResponseWriter, r *http.Request) {
	if !(r.Header.Get("Upgrade") == "websocket") {
		snapshot := statistic.DefaultManager.Snapshot()
		render.JSON(w, r, snapshot)
		return
	}

	intervalStr := r.URL.Query().Get("interval")
	interval := 1000
	if intervalStr != "" {
		t, err := strconv.Atoi(intervalStr)
		if err != nil || t <= 0 || int64(t) > math.MaxInt64/int64(time.Millisecond) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		interval = t
	}
	conn, _, err := wsUpgrade(r, w)
	if err != nil {
		return
	}
	defer conn.Close()
	ctx := streamContext(r, conn)

	buf := &bytes.Buffer{}
	sendSnapshot := func() error {
		buf.Reset()
		snapshot := statistic.DefaultManager.Snapshot()
		if err := json.NewEncoder(buf).Encode(snapshot); err != nil {
			return err
		}

		return wsWriteServerText(conn, buf.Bytes())
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	tick := time.NewTicker(time.Millisecond * time.Duration(interval))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if err := sendSnapshot(); err != nil {
			break
		}
	}
}

func closeConnection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if c := statistic.DefaultManager.Get(id); c != nil {
		_ = c.Close()
	}
	render.NoContent(w, r)
}

func closeAllConnections(w http.ResponseWriter, r *http.Request) {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
	render.NoContent(w, r)
}

func setSmartBlock(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if c := statistic.DefaultManager.Get(id); c != nil {
		c.Info().Metadata.SmartBlock = "blocked"
		_ = c.Close()
	}
	render.NoContent(w, r)
}
