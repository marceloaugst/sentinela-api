package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sentinela/internal/audit"
	"sentinela/internal/auth"
	"sentinela/internal/http/response"
	"sentinela/internal/users"
	"sentinela/internal/validation"
)

type Users struct {
	Svc        *auth.Service
	Log        *slog.Logger
	TrustProxy bool
}

func (h Users) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, users.ErrNotFound):
		response.NotFound(w)
	case errors.Is(err, users.ErrConflict):
		response.Error(w, http.StatusConflict, "CONFLICT", "Já existe um usuário com esse e-mail.")
	case errors.Is(err, users.ErrLastAdmin):
		response.Error(w, http.StatusConflict, "LAST_ADMIN", "Não é possível remover, desativar ou rebaixar o último administrador ativo.")
	default:
		h.Log.Error("erro em handler de usuários", "err", err)
		response.Internal(w)
	}
}

func (h Users) List(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, per := pagination(r, &p)
	q := r.URL.Query()
	lp := users.ListParams{Page: page, PerPage: per, Query: strings.TrimSpace(q.Get("q"))}
	if v := q.Get("role"); v != "" {
		if !users.ValidRole(v) {
			p.Add("role", "deve ser viewer, operator ou admin")
		}
		lp.Role = v
	}
	switch q.Get("is_active") {
	case "":
	case "true":
		t := true
		lp.Active = &t
	case "false":
		f := false
		lp.Active = &f
	default:
		p.Add("is_active", "deve ser true ou false")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Svc.Users.List(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(page, per, total))
}

func (h Users) Create(w http.ResponseWriter, r *http.Request) {
	var in users.CreateInput
	if !response.Decode(w, r, &in) {
		return
	}
	if p := in.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	u, err := h.Svc.CreateUser(r.Context(), auditCtx(r, h.TrustProxy), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/users/"+u.ID)
	response.JSON(w, http.StatusCreated, u, nil)
}

func (h Users) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	u, err := h.Svc.Users.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, u, nil)
}

func (h Users) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in users.UpdateInput
	if !response.Decode(w, r, &in) {
		return
	}
	cur, err := h.Svc.Users.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if p := in.Validate(cur); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	u, revoked, err := h.Svc.UpdateUser(r.Context(), auditCtx(r, h.TrustProxy), id, in)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, u, map[string]any{"revoked_sessions": revoked})
}

// POST /users/{id}/sessions/revoke
func (h Users) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	n, err := h.Svc.RevokeAll(r.Context(), auditCtx(r, h.TrustProxy), id, "admin_revoked", "")
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"revoked_sessions": n}, nil)
}

// ---- trilha de auditoria ----

type AuditLogs struct {
	List func(r *http.Request, p audit.ListParams) ([]audit.Entry, int, error)
	Log  *slog.Logger
}

func (h AuditLogs) Handle(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, per := pagination(r, &p)
	q := r.URL.Query()
	lp := audit.ListParams{Page: page, PerPage: per, Action: q.Get("action"), ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id")}
	if len(lp.Action) > 100 || len(lp.ResourceType) > 100 || len(lp.ResourceID) > 100 {
		p.Add("action", "valor longo demais")
	}
	if v := q.Get("actor_user_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("actor_user_id", "deve ser um UUID")
		}
		lp.ActorUserID = strings.ToLower(v)
	}
	lp.From, lp.To = parseTimeParam(&p, r, "from"), parseTimeParam(&p, r, "to")
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.List(r, lp)
	if err != nil {
		h.Log.Error("erro ao consultar auditoria", "err", err)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(page, per, total))
}
