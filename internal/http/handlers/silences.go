package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"sentinela/internal/http/response"
	"sentinela/internal/silences"
	"sentinela/internal/validation"
)

// Silences expõe silenciamentos e janelas de manutenção de alertas.
type Silences struct {
	Repo       *silences.Repository
	Log        *slog.Logger
	TrustProxy bool
}

func (h Silences) fail(w http.ResponseWriter, err error) {
	var p validation.Problems
	switch {
	case errors.Is(err, silences.ErrNotFound):
		response.NotFound(w)
	case errors.Is(err, silences.ErrUnknownServer):
		p.Add("server_id", "servidor não encontrado")
		response.Validation(w, p)
	case errors.Is(err, silences.ErrUnknownRule):
		p.Add("rule_id", "regra não encontrada")
		response.Validation(w, p)
	default:
		h.Log.Error("erro em handler de silenciamentos", "err", err)
		response.Internal(w)
	}
}

func (h Silences) List(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, per := pagination(r, &p)
	q := r.URL.Query()
	lp := silences.ListParams{Page: page, PerPage: per}
	switch v := q.Get("status"); v {
	case "", silences.StatusActive, silences.StatusScheduled, "ended":
		lp.Status = v
	default:
		p.Add("status", "deve ser active, scheduled ou ended")
	}
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		lp.ServerID = strings.ToLower(v)
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Repo.List(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(page, per, total))
}

func (h Silences) Create(w http.ResponseWriter, r *http.Request) {
	var in silences.CreateInput
	if !response.Decode(w, r, &in) {
		return
	}
	if p := in.Validate(time.Now().UTC()); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	s, err := h.Repo.Create(r.Context(), auditCtx(r, h.TrustProxy), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/silences/"+s.ID)
	response.JSON(w, http.StatusCreated, s, nil)
}

func (h Silences) Get(w http.ResponseWriter, r *http.Request) {
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

// DELETE /silences/{id}: encerra a janela agora (ou descarta a agendada). Idempotente.
func (h Silences) Cancel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	s, err := h.Repo.Cancel(r.Context(), auditCtx(r, h.TrustProxy), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, s, nil)
}
