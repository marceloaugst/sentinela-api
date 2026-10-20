package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/dashboard"
	"sentinela/internal/http/response"
	"sentinela/internal/metrics"
	"sentinela/internal/servers"
	"sentinela/internal/validation"
)

const maxDashboardServers = 50

type Dashboard struct {
	Dash    *dashboard.Repository
	Servers *servers.Repository
	Metrics *metrics.Repository
	Log     *slog.Logger
	Now     func() time.Time
}

func (h Dashboard) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h Dashboard) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, servers.ErrNotFound):
		response.NotFound(w)
	case errors.Is(err, metrics.ErrTooManyPoints):
		var p validation.Problems
		p.Add("interval", "o período geraria pontos demais; use um intervalo maior")
		response.Validation(w, p)
	default:
		h.Log.Error("erro em handler de dashboard", "err", err)
		response.Internal(w)
	}
}

type seriesMeta struct {
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Interval      string    `json:"interval"`
	BucketSeconds int       `json:"bucket_seconds"` // 0 = amostras originais
	Points        int       `json:"points"`
	MaxPoints     int       `json:"max_points"`
}

func newSeriesMeta(rg metrics.Range, points int) seriesMeta {
	return seriesMeta{From: rg.From, To: rg.To, Interval: rg.Interval.Name,
		BucketSeconds: int(rg.Interval.Dur.Seconds()), Points: points, MaxPoints: metrics.MaxPoints}
}

// GET /servers/{id}/metrics?from&to&interval
func (h Dashboard) ServerMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()
	rg, p := metrics.ResolveRange(q.Get("from"), q.Get("to"), q.Get("interval"), h.now(), true)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	points, err := h.Metrics.ServerSeries(r.Context(), id, rg)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, points, newSeriesMeta(rg, len(points)))
}

// GET /servers/{id}/summary
func (h Dashboard) ServerSummary(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	s, err := h.Dash.ServerSummary(r.Context(), h.Servers, h.Metrics, id, h.now())
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, s, nil)
}

// GET /dashboard/summary
func (h Dashboard) Summary(w http.ResponseWriter, r *http.Request) {
	o, err := h.Dash.Overview(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, o, nil)
}

// GET /dashboard/metrics?from&to&interval&server_id=a,b
func (h Dashboard) DashboardMetrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rg, p := metrics.ResolveRange(q.Get("from"), q.Get("to"), q.Get("interval"), h.now(), false)

	var ids []string
	for _, v := range q["server_id"] {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			if !uuidRe.MatchString(part) {
				p.Add("server_id", "contém identificador inválido")
				break
			}
			ids = append(ids, strings.ToLower(part))
		}
	}
	if len(ids) > maxDashboardServers {
		p.Add("server_id", "no máximo 50 servidores por consulta")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	points, err := h.Metrics.DashboardSeries(r.Context(), rg, ids)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, points, newSeriesMeta(rg, len(points)))
}

func limitParam(r *http.Request, p *validation.Problems) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 10
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 50 {
		p.Add("limit", "deve ser um inteiro entre 1 e 50")
		return 10
	}
	return n
}

// GET /dashboard/recent-alerts?limit&status=active|firing|acknowledged|resolved
func (h Dashboard) RecentAlerts(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	limit := limitParam(r, &p)
	status := r.URL.Query().Get("status")
	switch status {
	case "", "active", "firing", "acknowledged", "resolved":
	default:
		p.Add("status", "deve ser active, firing, acknowledged ou resolved")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, err := h.Dash.RecentAlerts(r.Context(), status, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, map[string]any{"limit": limit})
}

// GET /dashboard/recent-incidents?limit&status=open|resolved
func (h Dashboard) RecentIncidents(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	limit := limitParam(r, &p)
	status := r.URL.Query().Get("status")
	switch status {
	case "", "open", "resolved":
	default:
		p.Add("status", "deve ser open ou resolved")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, err := h.Dash.RecentIncidents(r.Context(), status, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, map[string]any{"limit": limit})
}
