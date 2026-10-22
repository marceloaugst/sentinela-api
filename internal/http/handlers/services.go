package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sentinela/internal/http/response"
	"sentinela/internal/servers"
	"sentinela/internal/services"
	"sentinela/internal/validation"
)

// Services expõe os serviços descobertos automaticamente (somente leitura: não há cadastro).
type Services struct {
	Repo    *services.Repository
	Servers *servers.Repository
	Log     *slog.Logger
}

func (h Services) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrNotFound), errors.Is(err, servers.ErrNotFound):
		response.NotFound(w)
	default:
		h.Log.Error("erro em handler de serviços", "err", err)
		response.Internal(w)
	}
}

func (h Services) listParams(r *http.Request, p *validation.Problems) services.ListParams {
	page, per := pagination(r, p)
	q := r.URL.Query()
	lp := services.ListParams{Page: page, PerPage: per, Query: strings.TrimSpace(q.Get("q"))}
	if len(lp.Query) > 120 {
		p.Add("q", "excede o tamanho máximo")
	}
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		lp.ServerID = strings.ToLower(v)
	}
	if v := q.Get("status"); v != "" {
		switch v {
		case services.StatusUp, services.StatusDown, services.StatusDegraded, services.StatusUnknown:
			lp.Status = v
		default:
			p.Add("status", "deve ser up, down, degraded ou unknown")
		}
	}
	if v := q.Get("service_type"); v != "" {
		switch v {
		case services.TypeDiscovered:
			lp.Type = v
		default:
			p.Add("service_type", "deve ser discovered")
		}
	}
	return lp
}

func (h Services) List(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	lp := h.listParams(r, &p)
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

// GET /servers/{id}/services
func (h Services) ListByServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var p validation.Problems
	lp := h.listParams(r, &p)
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

func (h Services) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	s, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, s, nil)
}
