package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/auth"
	"sentinela/internal/events"
	"sentinela/internal/http/response"
	"sentinela/internal/netutil"
	"sentinela/internal/validation"
)

// Events serve GET /api/v1/events (Server-Sent Events).
type Events struct {
	Hub          *events.Hub
	Log          *slog.Logger
	TrustProxy   bool
	Heartbeat    time.Duration // comentário ": ping" periódico (mantém proxies abertos e detecta clientes mortos)
	ReplayLimit  int           // máximo de eventos reenviados após Last-Event-ID; acima disso o cliente ressincroniza
	WriteTimeout time.Duration // prazo para cada escrita (cliente travado não prende a goroutine)
	// Valid reavalia a sessão a cada ping: sessão revogada, vencida ou usuário desativado encerra o stream.
	Valid func(ctx context.Context, p auth.Principal) bool
}

const retryHintMS = 5000

func (h Events) parse(r *http.Request) (f events.Filter, last int64, p validation.Problems) {
	q := r.URL.Query()
	if v := q.Get("types"); v != "" {
		f.Types = map[string]bool{}
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			if !events.ValidType(t) {
				p.Add("types", fmt.Sprintf("tipo desconhecido %q (válidos: %s)", t, strings.Join(events.AllTypes, ", ")))
				break
			}
			f.Types[t] = true
		}
	}
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		f.ServerID = strings.ToLower(v)
	}
	// O cabeçalho é enviado automaticamente pelo EventSource ao reconectar; clientes baseados em fetch
	// podem usar ?last_event_id=. O id não é um segredo.
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = q.Get("last_event_id")
	}
	if raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			p.Add("last_event_id", "deve ser um inteiro >= 0")
		}
		last = n
	}
	return f, last, p
}

func (h Events) Stream(w http.ResponseWriter, r *http.Request) {
	filter, last, p := h.parse(r)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	rc := http.NewResponseController(w)

	// Inscreve ANTES de ler o histórico: nenhum evento cai na fresta entre o replay e o ao vivo.
	sub, err := h.Hub.Subscribe(netutil.ClientIP(r, h.TrustProxy), filter)
	switch {
	case errors.Is(err, events.ErrTooManyPerIP):
		w.Header().Set("Retry-After", "10")
		response.Error(w, http.StatusTooManyRequests, "TOO_MANY_STREAMS", "Conexões de eventos demais para este endereço.")
		return
	case errors.Is(err, events.ErrTooManyClients), errors.Is(err, events.ErrHubClosed):
		w.Header().Set("Retry-After", "10")
		response.Error(w, http.StatusServiceUnavailable, "STREAM_UNAVAILABLE", "Stream de eventos indisponível no momento.")
		return
	case err != nil:
		h.Log.Error("falha ao assinar eventos", "err", err)
		response.Internal(w)
		return
	}
	defer sub.Close() // libera a vaga e o buffer em QUALQUER saída (cliente desconectou, erro, encerramento)

	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream; charset=utf-8")
	hdr.Set("Cache-Control", "no-cache, no-transform")
	hdr.Set("X-Accel-Buffering", "no") // Nginx: não armazenar a resposta em buffer
	w.WriteHeader(http.StatusOK)

	timeout := h.WriteTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// O WriteTimeout global do servidor (30 s) mataria o stream: cada escrita ganha o próprio prazo.
	send := func(fn func(io.Writer) error) error {
		_ = rc.SetWriteDeadline(time.Now().Add(timeout))
		if err := fn(w); err != nil {
			return err
		}
		return rc.Flush()
	}
	sendEvent := func(e events.Event) error { return send(func(w io.Writer) error { return events.WriteSSE(w, e) }) }
	resync := func(reason string) {
		_ = sendEvent(events.Event{Type: events.TypeResync, Time: time.Now().UTC(), Data: []byte(`{"reason":"` + reason + `"}`)})
	}

	if err := send(func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "retry: %d\n: connected\n\n", retryHintMS)
		return err
	}); err != nil {
		return
	}

	// ---- reconexão: reenvia o que o cliente perdeu ----
	lastSent := last
	if last > 0 {
		maxID, purged, err := h.Hub.Position(r.Context())
		if err != nil {
			h.Log.Error("falha ao ler posição do log de eventos", "err", err)
			resync("error")
			return
		}
		limit := h.ReplayLimit
		if limit <= 0 {
			limit = 1000
		}
		switch {
		case last < purged:
			resync("gap") // eventos antigos foram removidos pela retenção
			lastSent = maxID
		case last > maxID:
			resync("ahead") // id de outro histórico (ex.: banco recriado)
			lastSent = maxID
		default:
			missed, err := h.Hub.Replay(r.Context(), last, limit+1)
			if err != nil {
				h.Log.Error("falha no replay de eventos", "err", err)
				resync("error")
				return
			}
			if len(missed) > limit {
				// perdeu eventos demais para reenviar: o cliente recarrega o estado pela API e segue ao vivo
				resync("too_many")
				lastSent = missed[len(missed)-1].ID
				if mx, _, e := h.Hub.Position(r.Context()); e == nil {
					lastSent = mx
				}
				break
			}
			for _, e := range missed {
				lastSent = e.ID
				if filter.Match(e) {
					if sendEvent(e) != nil {
						return
					}
				}
			}
		}
	}

	hb := h.Heartbeat
	if hb <= 0 {
		hb = 15 * time.Second
	}
	ping := time.NewTicker(hb)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done(): // cliente foi embora
			return
		case <-ping.C:
			if h.Valid != nil {
				if p, ok := auth.PrincipalFrom(r.Context()); ok && !h.Valid(r.Context(), p) {
					return
				}
			}
			if send(func(w io.Writer) error { _, err := io.WriteString(w, ": ping\n\n"); return err }) != nil {
				return
			}
		case e, ok := <-sub.C:
			if !ok {
				if sub.Reason() == "overflow" {
					resync("overflow") // o cliente não acompanhou: deve recarregar o estado
				}
				return // "shutdown": o cliente reconecta sozinho (EventSource) e o replay cobre a fresta
			}
			if e.Durable() {
				if e.ID <= lastSent {
					continue // já enviado pelo replay
				}
				lastSent = e.ID
			}
			if sendEvent(e) != nil {
				return
			}
		}
	}
}
