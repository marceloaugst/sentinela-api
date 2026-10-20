package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"sentinela/internal/agents"
	"sentinela/internal/http/response"
	"sentinela/internal/servers"
	"sentinela/internal/validation"
)

type Servers struct {
	Repo       *servers.Repository
	Creds      *agents.Repository
	Log        *slog.Logger
	TrustProxy bool
}

func (h Servers) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, servers.ErrNotFound), errors.Is(err, agents.ErrServerNotFound),
		errors.Is(err, agents.ErrCredentialNotFound):
		response.NotFound(w)
	case errors.Is(err, servers.ErrConflict):
		response.Error(w, http.StatusConflict, "CONFLICT", "Já existe um servidor com esse nome.")
	default:
		h.Log.Error("erro em handler de servidores", "err", err)
		response.Internal(w)
	}
}

func (h Servers) List(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, perPage := pagination(r, &p)
	q := r.URL.Query()
	params := servers.ListParams{Page: page, PerPage: perPage, Query: strings.TrimSpace(q.Get("q"))}
	if len(params.Query) > 120 {
		p.Add("q", "excede o tamanho máximo")
	}
	if v := q.Get("status"); v != "" {
		switch v {
		case servers.StatusActive, servers.StatusMaintenance, servers.StatusDisabled:
			params.Status = v
		default:
			p.Add("status", "deve ser active, maintenance ou disabled")
		}
	}
	if v := q.Get("connection"); v != "" {
		switch v {
		case servers.ConnOnline, servers.ConnOffline, servers.ConnUnknown:
			params.Connection = v
		default:
			p.Add("connection", "deve ser online, offline ou unknown")
		}
	}
	params.Sort = "name"
	if v := q.Get("sort"); v != "" {
		if servers.SortAllowed(v) {
			params.Sort = v
		} else {
			p.Add("sort", "deve ser name, hostname, status, created_at ou last_seen_at")
		}
	}
	switch q.Get("order") {
	case "", "asc":
	case "desc":
		params.Desc = true
	default:
		p.Add("order", "deve ser asc ou desc")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Repo.List(r.Context(), params)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(page, perPage, total))
}

func (h Servers) Create(w http.ResponseWriter, r *http.Request) {
	var in servers.CreateInput
	if !response.Decode(w, r, &in) {
		return
	}
	if p := in.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	s, err := h.Repo.Create(r.Context(), auditCtx(r, h.TrustProxy), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/servers/"+s.ID)
	response.JSON(w, http.StatusCreated, s, nil)
}

func (h Servers) Get(w http.ResponseWriter, r *http.Request) {
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

func (h Servers) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in servers.UpdateInput
	if !response.Decode(w, r, &in) {
		return
	}
	if p := in.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	s, err := h.Repo.Update(r.Context(), auditCtx(r, h.TrustProxy), id, in)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, s, nil)
}

func (h Servers) Delete(w http.ResponseWriter, r *http.Request) {
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

func (h Servers) Disks(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	disks, err := h.Repo.Disks(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, disks, nil)
}

// --- credenciais de agente ---

type issueInput struct {
	ExpiresInDays *int `json:"expires_in_days"`
	Replace       bool `json:"replace"`
}

type issuedCredential struct {
	agents.Credential
	Token string `json:"token"` // exibido somente nesta resposta
}

func (h Servers) IssueCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in issueInput
	// corpo é opcional: sem corpo => padrões
	if r.ContentLength != 0 {
		if !response.Decode(w, r, &in) {
			return
		}
	}
	var expires *time.Time
	if in.ExpiresInDays != nil {
		if *in.ExpiresInDays < 1 || *in.ExpiresInDays > 3650 {
			var p validation.Problems
			p.Add("expires_in_days", "deve estar entre 1 e 3650")
			response.Validation(w, p)
			return
		}
		t := time.Now().Add(time.Duration(*in.ExpiresInDays) * 24 * time.Hour).UTC()
		expires = &t
	}
	cred, token, err := h.Creds.Issue(r.Context(), auditCtx(r, h.TrustProxy), id, expires, in.Replace)
	if err != nil {
		h.fail(w, err)
		return
	}
	// o token não deve ser armazenado em cache por intermediários
	w.Header().Set("Cache-Control", "no-store")
	response.JSON(w, http.StatusCreated, issuedCredential{Credential: cred, Token: token}, nil)
}

func (h Servers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	list, err := h.Creds.List(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, nil)
}

func (h Servers) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	credID, ok := pathUUID(w, r, "credentialId")
	if !ok {
		return
	}
	if err := h.Creds.Revoke(r.Context(), auditCtx(r, h.TrustProxy), id, credID); err != nil {
		h.fail(w, err)
		return
	}
	response.NoContent(w)
}
