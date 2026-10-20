package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"sentinela/internal/http/response"
	"sentinela/internal/notifications"
	"sentinela/internal/validation"
)

type Channels struct {
	Repo       *notifications.ChannelRepository
	Log        *slog.Logger
	TrustProxy bool
}

func (h Channels) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, notifications.ErrChannelNotFound):
		response.NotFound(w)
	case errors.Is(err, notifications.ErrNoSecretsKey):
		response.Error(w, http.StatusServiceUnavailable, "SECRETS_NOT_CONFIGURED",
			"SECRETS_KEY não configurada: não é possível armazenar tokens de forma segura.")
	case errors.Is(err, notifications.ErrChatNotAllowed):
		var p validation.Problems
		p.Add("chat_id", "destino não autorizado (configure TELEGRAM_ALLOWED_CHAT_IDS)")
		response.Validation(w, p)
	default:
		h.Log.Error("erro em handler de canais", "err", err)
		response.Internal(w)
	}
}

func (h Channels) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.Repo.List(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, nil)
}

func (h Channels) Create(w http.ResponseWriter, r *http.Request) {
	var in notifications.CreateInput
	if !response.Decode(w, r, &in) {
		return
	}
	if p := in.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	c, err := h.Repo.Create(r.Context(), auditCtx(r, h.TrustProxy), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/notification-channels/"+c.ID)
	response.JSON(w, http.StatusCreated, c, nil)
}

func (h Channels) Get(w http.ResponseWriter, r *http.Request) {
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

func (h Channels) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in notifications.UpdateInput
	if !response.Decode(w, r, &in) {
		return
	}
	if p := in.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	c, err := h.Repo.Update(r.Context(), auditCtx(r, h.TrustProxy), id, in)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, c, nil)
}

func (h Channels) Delete(w http.ResponseWriter, r *http.Request) {
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

// POST /notification-channels/{id}/test: enfileira uma mensagem de teste (entregue pelo worker).
func (h Channels) Test(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.Repo.EnqueueTest(r.Context(), id); err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusAccepted, map[string]any{"queued": true}, nil)
}
