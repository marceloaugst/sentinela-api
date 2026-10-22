package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/http/response"
	"sentinela/internal/notifications"
	"sentinela/internal/validation"
)

// Notifications expõe o registro permanente de notificações (tabela notifications, no PostgreSQL).
type Notifications struct {
	Store      *notifications.Store
	Log        *slog.Logger
	TrustProxy bool
}

var notificationKinds = map[string]bool{"alert_triggered": true, "alert_resolved": true, "ip_banned": true}

func (h Notifications) List(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, per := pagination(r, &p)
	q := r.URL.Query()
	lp := notifications.ListParams{Page: page, PerPage: per}
	if v := q.Get("kind"); v != "" {
		if !notificationKinds[v] {
			p.Add("kind", "deve ser alert_triggered, alert_resolved ou ip_banned")
		}
		lp.Kind = v
	}
	lp.Priority = priorityParam(&p, q.Get("priority"))
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		lp.ServerID = strings.ToLower(v)
	}
	switch v := q.Get("unread"); v {
	case "":
	case "true":
		lp.Unread = true
	case "false":
	default:
		p.Add("unread", "deve ser true ou false")
	}
	lp.From, lp.To = parseTimeParam(&p, r, "from"), parseTimeParam(&p, r, "to")
	if lp.From != nil && lp.To != nil && !lp.From.Before(*lp.To) {
		p.Add("from", "deve ser anterior a 'to'")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Store.List(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	unread, err := h.Store.UnreadCount(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	meta := struct {
		pageMeta
		Unread int `json:"unread"`
	}{newPageMeta(page, per, total), unread}
	response.JSON(w, http.StatusOK, list, meta)
}

func (h Notifications) MarkRead(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		response.BadRequest(w, "INVALID_ID", "Identificador inválido.")
		return
	}
	n, err := h.Store.MarkRead(r.Context(), id, auditCtx(r, h.TrustProxy).UserID)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, n, nil)
}

func (h Notifications) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	n, err := h.Store.MarkAllRead(r.Context(), auditCtx(r, h.TrustProxy).UserID)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"marked": n}, nil)
}

func (h Notifications) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, notifications.ErrNotFound) {
		response.NotFound(w)
		return
	}
	h.Log.Error("erro em handler de notificações", "err", err)
	response.Internal(w)
}
