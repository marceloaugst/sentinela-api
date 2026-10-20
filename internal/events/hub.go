package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/telemetry"
)

var (
	ErrTooManyClients = errors.New("limite de conexões de eventos atingido")
	ErrTooManyPerIP   = errors.New("limite de conexões de eventos por endereço atingido")
	ErrHubClosed      = errors.New("servidor encerrando")
)

// Filter restringe o que uma assinatura recebe. Sem Types, recebe todos os tipos DURÁVEIS
// (metrics.updated é opt-in: é de alta frequência e deve ser pedido explicitamente).
type Filter struct {
	Types    map[string]bool
	ServerID string
}

func (f Filter) Match(e Event) bool {
	if len(f.Types) > 0 {
		if !f.Types[e.Type] {
			return false
		}
	} else if e.Type == TypeMetricsUpdated {
		return false
	}
	return f.ServerID == "" || e.ServerID == f.ServerID
}

// Sub é uma assinatura (uma conexão SSE). C é fechado quando a assinatura termina; Reason diz por quê.
type Sub struct {
	C      chan Event
	hub    *Hub
	ip     string
	filter Filter
	closed bool
	reason string
}

// Reason: "overflow" (cliente lento), "shutdown" (servidor encerrando) ou "client".
func (s *Sub) Reason() string {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	return s.reason
}

func (s *Sub) Close() {
	s.hub.mu.Lock()
	s.hub.closeSubLocked(s, "client")
	s.hub.mu.Unlock()
}

// Hub distribui eventos aos assinantes DESTA instância. Cada instância da API roda um Hub que lê o
// mesmo log do PostgreSQL, então funciona com várias instâncias sem broker externo.
type Hub struct {
	URL     string // conexão dedicada para LISTEN (fora do pool)
	Pool    *pgxpool.Pool
	Log     *slog.Logger
	Metrics *telemetry.Metrics

	MaxClients   int
	MaxPerIP     int
	Buffer       int           // eventos pendentes por cliente antes de considerá-lo lento
	PollInterval time.Duration // rede de segurança caso um NOTIFY se perca

	mu     sync.Mutex
	subs   map[*Sub]struct{}
	perIP  map[string]int
	closed bool

	cursor    int64
	ready     chan struct{}
	readyOnce sync.Once
}

func NewHub(url string, pool *pgxpool.Pool, log *slog.Logger, m *telemetry.Metrics) *Hub {
	return &Hub{URL: url, Pool: pool, Log: log, Metrics: m, MaxClients: 500, MaxPerIP: 20, Buffer: 256,
		PollInterval: 5 * time.Second, subs: map[*Sub]struct{}{}, perIP: map[string]int{}, ready: make(chan struct{})}
}

// Ready é fechado quando o LISTEN está ativo (útil em testes e na partida).
func (h *Hub) Ready() <-chan struct{} { return h.ready }

func (h *Hub) Clients() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.subs) }

func (h *Hub) Subscribe(ip string, f Filter) (*Sub, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.closed:
		return nil, ErrHubClosed
	case h.MaxClients > 0 && len(h.subs) >= h.MaxClients:
		return nil, ErrTooManyClients
	case h.MaxPerIP > 0 && h.perIP[ip] >= h.MaxPerIP:
		return nil, ErrTooManyPerIP
	}
	s := &Sub{C: make(chan Event, h.Buffer), hub: h, ip: ip, filter: f}
	h.subs[s] = struct{}{}
	h.perIP[ip]++
	if h.Metrics != nil {
		h.Metrics.SSEClients.Inc()
	}
	return s, nil
}

func (h *Hub) closeSubLocked(s *Sub, reason string) {
	if s.closed {
		return
	}
	s.closed, s.reason = true, reason
	close(s.C)
	delete(h.subs, s)
	if h.perIP[s.ip]--; h.perIP[s.ip] <= 0 {
		delete(h.perIP, s.ip)
	}
	if h.Metrics != nil {
		h.Metrics.SSEClients.Dec()
	}
}

// Broadcast entrega o evento às assinaturas locais que o aceitam. Nunca bloqueia: um cliente que não
// acompanha (buffer cheio) é desconectado e deve reconectar com Last-Event-ID (ou ressincronizar).
func (h *Hub) Broadcast(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if !s.filter.Match(ev) {
			continue
		}
		select {
		case s.C <- ev:
			if h.Metrics != nil {
				h.Metrics.SSEEvents.WithLabelValues("delivered").Inc()
			}
		default:
			h.closeSubLocked(s, "overflow")
			if h.Metrics != nil {
				h.Metrics.SSEEvents.WithLabelValues("overflow").Inc()
			}
		}
	}
}

// Close encerra todas as assinaturas (usado no desligamento gracioso, para que as conexões longas
// não impeçam o servidor de terminar).
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for s := range h.subs {
		h.closeSubLocked(s, "shutdown")
	}
}

// ---- leitura do log ----

func scanEvents(rows pgx.Rows) ([]Event, error) {
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var data []byte
		if err := rows.Scan(&e.ID, &e.Type, &e.ServerID, &data, &e.Time); err != nil {
			return nil, err
		}
		e.Data = data
		out = append(out, e)
	}
	return out, rows.Err()
}

const eventCols = `id, type, COALESCE(server_id::text, ''), data, created_at`

// Replay devolve até limit eventos duráveis com id > after, em ordem.
func (h *Hub) Replay(ctx context.Context, after int64, limit int) ([]Event, error) {
	rows, err := h.Pool.Query(ctx, `SELECT `+eventCols+` FROM events WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// Position informa o maior id existente e o maior id já removido pela retenção.
func (h *Hub) Position(ctx context.Context) (maxID, purgedUntil int64, err error) {
	err = h.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT max(id) FROM events), 0),
		COALESCE((SELECT purged_until FROM event_log_state), 0)`).Scan(&maxID, &purgedUntil)
	return
}

// Purge remove eventos anteriores a before e registra o maior id removido.
func Purge(ctx context.Context, pool *pgxpool.Pool, before time.Time) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var n, maxID int64
	if err := tx.QueryRow(ctx, `WITH d AS (DELETE FROM events WHERE created_at < $1 RETURNING id)
		SELECT count(*), COALESCE(max(id), 0) FROM d`, before).Scan(&n, &maxID); err != nil {
		return 0, err
	}
	if n > 0 {
		if _, err := tx.Exec(ctx, `UPDATE event_log_state SET purged_until = GREATEST(purged_until, $1)`, maxID); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit(ctx)
}

// pull lê do log tudo que passou do cursor e distribui. Idempotente; chamado a cada NOTIFY e no polling.
func (h *Hub) pull(ctx context.Context) error {
	for {
		evs, err := h.Replay(ctx, h.cursor, 500)
		if err != nil {
			return err
		}
		for _, e := range evs {
			h.cursor = e.ID
			h.Broadcast(e)
		}
		if len(evs) < 500 {
			return nil
		}
	}
}

// Run mantém o LISTEN e distribui eventos até o contexto terminar. Reconecta com backoff; ao
// reconectar, o pull recupera o que foi publicado enquanto estava desconectado.
func (h *Hub) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := h.listen(ctx)
		if ctx.Err() != nil {
			return
		}
		h.Log.Warn("conexão de eventos perdida; reconectando", "err", err, "in", backoff.String())
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
}

func (h *Hub) listen(ctx context.Context) error {
	cfg, err := pgx.ParseConfig(h.URL)
	if err != nil {
		return err
	}
	cfg.RuntimeParams["application_name"] = "sentinela-events"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn.Close(cctx)
	}()
	var schema string
	if err := conn.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return err
	}
	liveChan := channelLivePrefix + schema
	for _, ch := range []string{channelDurablePrefix + schema, liveChan} {
		if _, err := conn.Exec(ctx, `LISTEN `+pgx.Identifier{ch}.Sanitize()); err != nil {
			return err
		}
	}
	if h.cursor == 0 { // primeira partida: só eventos futuros
		if err := h.Pool.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM events`).Scan(&h.cursor); err != nil {
			return err
		}
	}
	if err := h.pull(ctx); err != nil { // recupera o que ocorreu enquanto desconectado
		return err
	}
	h.readyOnce.Do(func() { close(h.ready) })

	poll := h.PollInterval
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for {
		wctx, cancel := context.WithTimeout(ctx, poll)
		n, err := conn.WaitForNotification(wctx)
		cancel()
		switch {
		case err == nil:
			if n.Channel == liveChan {
				h.broadcastLive(n.Payload)
			} else if _, perr := strconv.ParseInt(n.Payload, 10, 64); perr == nil {
				if err := h.pull(ctx); err != nil {
					return err
				}
			}
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.Is(err, context.DeadlineExceeded):
			if err := h.pull(ctx); err != nil { // rede de segurança contra NOTIFY perdido
				return err
			}
		default:
			return err
		}
	}
}

func (h *Hub) broadcastLive(payload string) {
	var p livePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil || !ValidType(p.Type) {
		return
	}
	h.Broadcast(Event{Type: p.Type, Time: p.Time, Data: p.Data, ServerID: p.ServerID})
}
