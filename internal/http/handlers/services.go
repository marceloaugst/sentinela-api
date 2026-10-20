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

type Services struct {
	Repo       *services.Repository
	Servers    *servers.Repository
	Validator  services.Validator
	Runner     *services.Runner
	Log        *slog.Logger
	TrustProxy bool
}

func (h Services) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrNotFound), errors.Is(err, servers.ErrNotFound):
		response.NotFound(w)
	case errors.Is(err, services.ErrServerNotFound):
		var p validation.Problems
		p.Add("server_id", "servidor não encontrado")
		response.Validation(w, p)
	case errors.Is(err, services.ErrConflict):
		response.Error(w, http.StatusConflict, "CONFLICT", "Já existe um serviço com esse nome neste servidor.")
	case errors.Is(err, services.ErrNotCentral):
		response.Error(w, http.StatusConflict, "CHECK_NOT_CENTRAL",
			"Serviços tcp e systemd são verificados pelo agente do servidor, em seu próprio intervalo.")
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
		case services.TypeHTTP, services.TypeTCP, services.TypeSystemd:
			lp.Type = v
		default:
			p.Add("service_type", "deve ser http, tcp ou systemd")
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

func (h Services) Create(w http.ResponseWriter, r *http.Request) {
	var in services.CreateInput
	if !response.Decode(w, r, &in) {
		return
	}
	cfg, p := h.Validator.Create(&in)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	s, err := h.Repo.Create(r.Context(), auditCtx(r, h.TrustProxy), in, cfg)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/services/"+s.ID)
	response.JSON(w, http.StatusCreated, s, nil)
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

func (h Services) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in services.UpdateInput
	if !response.Decode(w, r, &in) {
		return
	}
	cur, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	cfg, p := h.Validator.Update(cur, &in)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	s, err := h.Repo.Update(r.Context(), auditCtx(r, h.TrustProxy), id, in, cfg)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, s, nil)
}

func (h Services) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.Repo.Delete(r.Context(), auditCtx(r, h.TrustProxy), id); err != nil {
		h.fail(w, err)
		return
	}
	response.NoContent(w)
}

type checkResult struct {
	Status     string  `json:"status"`
	LatencyMS  *int    `json:"latency_ms"`
	StatusCode *int    `json:"status_code"`
	Error      *string `json:"error"`
}

// POST /services/{id}/check: executa agora a verificação de um serviço http.
func (h Services) Check(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	s, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	res, err := h.Runner.CheckOne(r.Context(), s)
	if err != nil {
		h.fail(w, err)
		return
	}
	updated, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	cr := checkResult{Status: res.Status, LatencyMS: res.LatencyMS, StatusCode: res.StatusCode}
	if res.Error != "" {
		cr.Error = &res.Error
	}
	response.JSON(w, http.StatusOK, map[string]any{"service": updated, "result": cr}, nil)
}
