package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/dockerhost"
	"sentinela/internal/http/response"
	"sentinela/internal/servers"
	"sentinela/internal/svcactions"
	"sentinela/internal/validation"
)

// MaxDockerBodyBytes cobre até 100 containers, com erro e fim do log dos inativos.
const MaxDockerBodyBytes = 512 << 10

// Docker expõe os containers do servidor (enviados pelo agente) e os pedidos de iniciar/reiniciar.
type Docker struct {
	Repo    *dockerhost.Repository
	Actions *svcactions.Repository
	Servers *servers.Repository
	Log     *slog.Logger

	TrustProxy bool
}

type dockerSummary struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Stopped int `json:"stopped"` // inativos: parados, encerrados, criados e nunca iniciados
	Other   int `json:"other"`   // pausados ou em transição
}

func summarizeContainers(list []dockerhost.Container) dockerSummary {
	s := dockerSummary{Total: len(list)}
	for _, c := range list {
		switch c.State {
		case "running", "restarting":
			s.Running++
		case "exited", "created", "dead":
			s.Stopped++
		default:
			s.Other++
		}
	}
	return s
}

// GET /servers/{id}/docker: se o servidor tem Docker e a lista de containers. Cada container traz `actions`
// (restart se ativo, start se inativo) e, quando inativo, `error` e `log_tail` com o que aconteceu.
func (h Docker) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		if errors.Is(err, servers.ErrNotFound) {
			response.NotFound(w)
			return
		}
		h.Log.Error("falha ao buscar servidor", "err", err)
		response.Internal(w)
		return
	}
	rep, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.Log.Error("falha ao ler containers do servidor", "err", err, "server_id", id)
		response.Internal(w)
		return
	}
	if rep == nil {
		response.JSON(w, http.StatusOK, map[string]any{
			"status": "unknown", "message": "O agente ainda não informou o estado do Docker deste servidor.",
			"checked_at": nil, "summary": dockerSummary{}, "containers": []dockerhost.Container{},
		}, nil)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"status": rep.Status, "message": rep.Message, "checked_at": rep.CheckedAt,
		"summary": summarizeContainers(rep.Containers), "containers": rep.Containers,
	}, nil)
}

// POST /servers/{id}/docker/containers/{containerId}/actions: pede ao agente para iniciar ou reiniciar o container.
// Responde 202; acompanhe por GET /service-commands/{id} (o mesmo dos serviços).
func (h Docker) Request(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	cid := chi.URLParam(r, "containerId")
	if !dockerhost.ValidID(cid) {
		response.NotFound(w)
		return
	}
	var in actionInput
	if !response.Decode(w, r, &in) {
		return
	}
	if !dockerhost.ValidAction(in.Action) {
		response.Validation(w, validation.Problems{{Field: "action", Message: "deve ser start ou restart"}})
		return
	}
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		if errors.Is(err, servers.ErrNotFound) {
			response.NotFound(w)
			return
		}
		h.Log.Error("falha ao buscar servidor", "err", err)
		response.Internal(w)
		return
	}
	cmd, err := h.Actions.RequestContainer(r.Context(), auditCtx(r, h.TrustProxy), id, cid, in.Action)
	switch {
	case err == nil:
		response.JSON(w, http.StatusAccepted, cmd, nil)
	case errors.Is(err, svcactions.ErrNoDiscovery):
		response.NotFound(w)
	case errors.Is(err, svcactions.ErrNotActionable):
		response.Error(w, http.StatusUnprocessableEntity, "ACTION_NOT_ALLOWED",
			"Esta ação não é permitida para o estado atual do container (ativo só reinicia; inativo só inicia).")
	case errors.Is(err, svcactions.ErrBusy):
		response.Error(w, http.StatusConflict, "COMMAND_IN_PROGRESS", "Já existe um comando em andamento para este container.")
	default:
		h.Log.Error("erro ao pedir ação em container", "err", err, "server_id", id)
		response.Internal(w)
	}
}

// ---- agente ----

// POST /agent/docker: retrato do Docker do servidor da credencial.
func (h Agent) PostDocker(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var rep dockerhost.Report
	if !response.Decode(w, r, &rep) {
		return
	}
	if p := rep.Validate(h.now()); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if err := h.Docker.Replace(r.Context(), id.ServerID, rep); err != nil {
		h.Log.Error("falha ao gravar retrato do Docker", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"stored": len(rep.Containers)}, nil)
}
