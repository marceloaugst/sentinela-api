package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"sentinela/internal/discovery"
	"sentinela/internal/http/response"
	"sentinela/internal/servers"
)

type Discovery struct {
	Repo    *discovery.Repository
	Servers *servers.Repository
	Log     *slog.Logger
}

// GET /servers/{id}/discovery: serviços descobertos automaticamente, com disponibilidade e o que
// fazer para os indisponíveis. Sem relatório do agente ainda, "services" vem vazio.
func (h Discovery) ListByServer(w http.ResponseWriter, r *http.Request) {
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
	items, err := h.Repo.List(r.Context(), id)
	if err != nil {
		h.Log.Error("falha ao listar descoberta de serviços", "err", err, "server_id", id)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"summary":    discovery.Summarize(items),
		"services":   items,
		"checked_at": latestCheck(items),
	}, nil)
}

func latestCheck(items []discovery.Item) any {
	if len(items) == 0 {
		return nil
	}
	t := items[0].CheckedAt
	for _, it := range items[1:] {
		if it.CheckedAt.After(t) {
			t = it.CheckedAt
		}
	}
	return t
}
