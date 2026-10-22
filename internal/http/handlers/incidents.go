package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sentinela/internal/http/response"
	"sentinela/internal/incidents"
	"sentinela/internal/servers"
	"sentinela/internal/validation"
)

type Incidents struct {
	Repo    *incidents.Repository
	Servers *servers.Repository
	Log     *slog.Logger
}

func (h Incidents) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, incidents.ErrNotFound), errors.Is(err, servers.ErrNotFound):
		response.NotFound(w)
	default:
		h.Log.Error("erro em handler de incidentes", "err", err)
		response.Internal(w)
	}
}

func (h Incidents) params(r *http.Request, p *validation.Problems) incidents.ListParams {
	page, per := pagination(r, p)
	q := r.URL.Query()
	lp := incidents.ListParams{Page: page, PerPage: per}
	switch v := q.Get("status"); v {
	case "", "open", "resolved":
		lp.Status = v
	default:
		p.Add("status", "deve ser open ou resolved")
	}
	switch v := q.Get("severity"); v {
	case "", "info", "warning", "critical":
		lp.Severity = v
	default:
		p.Add("severity", "deve ser info, warning ou critical")
	}
	lp.Priority = priorityParam(p, q.Get("priority"))
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		lp.ServerID = strings.ToLower(v)
	}
	lp.From, lp.To = parseTimeParam(p, r, "from"), parseTimeParam(p, r, "to")
	if lp.From != nil && lp.To != nil && !lp.From.Before(*lp.To) {
		p.Add("from", "deve ser anterior a 'to'")
	}
	return lp
}

func (h Incidents) List(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	lp := h.params(r, &p)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Repo.List(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(lp.Page, lp.PerPage, total))
}

// GET /servers/{id}/incidents
func (h Incidents) ListByServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var p validation.Problems
	lp := h.params(r, &p)
	lp.ServerID = id
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	list, total, err := h.Repo.List(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(lp.Page, lp.PerPage, total))
}

func (h Incidents) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	d, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, d, nil)
}

func (h Incidents) Events(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	ev, err := h.Repo.Events(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, ev, nil)
}
