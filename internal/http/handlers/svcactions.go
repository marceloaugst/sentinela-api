package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/discovery"
	"sentinela/internal/http/response"
	"sentinela/internal/servers"
	"sentinela/internal/svcactions"
	"sentinela/internal/validation"
)

// ServiceActions expõe os pedidos de iniciar/parar/reiniciar serviços e o resultado deles.
type ServiceActions struct {
	Repo       *svcactions.Repository
	Servers    *servers.Repository
	Log        *slog.Logger
	TrustProxy bool
}

func (h ServiceActions) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svcactions.ErrNotFound), errors.Is(err, svcactions.ErrNoDiscovery), errors.Is(err, servers.ErrNotFound):
		response.NotFound(w)
	case errors.Is(err, svcactions.ErrNotActionable):
		response.Error(w, http.StatusUnprocessableEntity, "ACTION_NOT_ALLOWED",
			"Esta ação não é permitida para o estado atual do serviço (só unidades systemd; o SSH não pode ser parado).")
	case errors.Is(err, svcactions.ErrBusy):
		response.Error(w, http.StatusConflict, "COMMAND_IN_PROGRESS", "Já existe um comando em andamento para este serviço.")
	case errors.Is(err, svcactions.ErrInvalidState):
		response.Error(w, http.StatusConflict, "INVALID_STATE", "O estado atual do comando não permite esta operação.")
	default:
		h.Log.Error("erro em handler de comandos de serviço", "err", err)
		response.Internal(w)
	}
}

type actionInput struct {
	Action string `json:"action"`
}

// POST /servers/{id}/services/{key}/actions: pede ao agente para iniciar, parar ou reiniciar o serviço.
// Responde 202: a execução é assíncrona (acompanhe por GET /service-commands/{id}).
func (h ServiceActions) Request(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	key := chi.URLParam(r, "key")
	if _, ok := discovery.Lookup(key); !ok {
		response.NotFound(w)
		return
	}
	var in actionInput
	if !response.Decode(w, r, &in) {
		return
	}
	var p validation.Problems
	if !svcactions.ValidAction(in.Action) {
		p.Add("action", "deve ser start, stop ou restart")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	cmd, err := h.Repo.Request(r.Context(), auditCtx(r, h.TrustProxy), id, key, in.Action)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusAccepted, cmd, nil)
}

// GET /servers/{id}/service-commands?limit=
func (h ServiceActions) ListByServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			response.Validation(w, validation.Problems{{Field: "limit", Message: "deve ser um inteiro entre 1 e 100"}})
			return
		}
		limit = n
	}
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	list, err := h.Repo.List(r.Context(), id, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, nil)
}

// GET /service-commands/{id}
func (h ServiceActions) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, c, nil)
}

// ---- agente ----

// GET /agent/commands: comandos pendentes do servidor da credencial (viram "em execução").
func (h Agent) Commands(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	list, err := h.SvcCommands.Claim(r.Context(), id.ServerID)
	if err != nil {
		h.Log.Error("falha ao buscar comandos do agente", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, list, nil)
}

// POST /agent/commands/{id}/result
func (h Agent) CommandResult(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	cmdID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var res svcactions.Result
	if !response.Decode(w, r, &res) {
		return
	}
	if p := res.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if err := h.SvcCommands.Complete(r.Context(), id.ServerID, cmdID, res); err != nil {
		switch {
		case errors.Is(err, svcactions.ErrNotFound):
			response.NotFound(w)
		case errors.Is(err, svcactions.ErrInvalidState):
			response.Error(w, http.StatusConflict, "INVALID_STATE", "O comando não está em execução.")
		default:
			h.Log.Error("falha ao gravar resultado do comando", "err", err, "server_id", id.ServerID)
			response.Internal(w)
		}
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"stored": true}, nil)
}
