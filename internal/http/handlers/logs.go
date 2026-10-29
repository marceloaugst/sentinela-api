package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"sentinela/internal/events"
	"sentinela/internal/http/response"
	"sentinela/internal/ipintel"
	"sentinela/internal/logs"
	"sentinela/internal/logstore"
	"sentinela/internal/notifications"
	"sentinela/internal/validation"
)

// MaxLogBatchBytes limita o corpo de POST /agent/logs (até 500 entradas).
const MaxLogBatchBytes = 1 << 20

const (
	maxLogRange    = 31 * 24 * time.Hour
	maxBanEvents   = 20               // eventos SSE de ban por lote
	banEventMaxAge = 10 * time.Minute // não reanuncia bans antigos (ex.: leitura desde o início do arquivo)
)

// LogStore é o que os handlers precisam do armazenamento de logs (ClickHouse).
type LogStore interface {
	Ready() bool
	Insert(ctx context.Context, serverID, batchID string, entries []logs.Entry) error
	List(ctx context.Context, f logstore.Filter, page, perPage int) ([]logstore.Row, int, error)
	Stats(ctx context.Context, f logstore.Filter) (logstore.Stats, error)
	IPTotals(ctx context.Context, f logstore.Filter, metric string, limit int) ([]logstore.IPTotal, int64, error)
}

// IPIntel enriquece IPs com país, provedor e reputação. Opcional.
type IPIntel interface {
	Lookup(ctx context.Context, ips []string) map[string]ipintel.Info
}

type Logs struct {
	Store LogStore // nil = recurso desativado (CLICKHOUSE_URL vazia)
	Intel IPIntel  // nil = respostas sem "geo"
	Pool  *pgxpool.Pool
	Log   *slog.Logger
	// Entries conta entradas por resultado (stored|duplicate|error); opcional.
	Entries *prometheus.CounterVec
	Now     func() time.Time

	once sync.Once
	seen *recentBatches
}

func (h *Logs) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Logs) count(result string, n int) {
	if h.Entries != nil {
		h.Entries.WithLabelValues(result).Add(float64(n))
	}
}

func (h *Logs) available(w http.ResponseWriter) bool {
	if h.Store == nil || !h.Store.Ready() {
		response.Error(w, http.StatusServiceUnavailable, "LOGS_UNAVAILABLE", "O armazenamento de logs não está disponível.")
		return false
	}
	return true
}

// PostLogs recebe um lote do agente. O servidor vem SEMPRE da credencial.
func (h *Logs) PostLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	if !h.available(w) {
		return
	}
	var b logs.Batch
	if !response.Decode(w, r, &b) {
		return
	}
	now := h.now()
	if p := b.Validate(now); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	h.once.Do(func() { h.seen = newRecentBatches(10*time.Minute, 20000) })
	key := id.ServerID + ":" + b.BatchID
	if h.seen.has(key, now) { // reenvio de um lote já gravado (a resposta anterior se perdeu)
		h.count("duplicate", len(b.Entries))
		response.JSON(w, http.StatusOK, map[string]any{"stored": 0, "duplicate": true}, nil)
		return
	}
	if err := h.Store.Insert(r.Context(), id.ServerID, b.BatchID, b.Entries); err != nil {
		h.count("error", len(b.Entries))
		h.Log.Error("falha ao gravar logs", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	h.seen.add(key, now)
	h.count("stored", len(b.Entries))
	h.publishBans(r.Context(), id.ServerID, b.Entries, now)
	response.JSON(w, http.StatusOK, map[string]any{"stored": len(b.Entries), "duplicate": false}, nil)
}

// publishBans anuncia os bans recentes do fail2ban: grava a notificação no PostgreSQL (registro permanente),
// enfileira o envio aos canais e publica o evento SSE. Melhor esforço: o lote já foi gravado no ClickHouse.
func (h *Logs) publishBans(ctx context.Context, serverID string, entries []logs.Entry, now time.Time) {
	if h.Pool == nil {
		return
	}
	var serverName string
	sent := 0
	for _, e := range entries {
		if e.Source != logs.SourceFail2ban || e.Type != logs.TypeBan || now.Sub(e.Time) > banEventMaxAge {
			continue
		}
		if sent++; sent > maxBanEvents {
			return
		}
		tx, err := h.Pool.Begin(ctx)
		if err != nil {
			h.Log.Warn("evento de ban não publicado", "err", err)
			return
		}
		if serverName == "" {
			if err = tx.QueryRow(ctx, `SELECT name FROM servers WHERE id = $1`, serverID).Scan(&serverName); err != nil {
				_ = tx.Rollback(ctx)
				h.Log.Warn("evento de ban não publicado", "err", err)
				return
			}
		}
		jail := e.Fields["jail"]
		msg := "IP " + e.IP
		if jail != "" {
			msg += " banido na jail " + jail
		}
		err = notifications.EnqueueEvent(ctx, tx, notifications.Payload{
			Kind: notifications.KindIPBanned, ServerID: serverID, ServerName: serverName, RuleName: e.IP,
			Severity: "warning", Priority: 3, Message: msg, At: e.Time,
		}, "ban:"+serverID+":"+e.IP+":"+e.Time.UTC().Format(time.RFC3339Nano))
		if err == nil {
			err = events.Publish(ctx, tx, events.TypeSecurityBan, serverID,
				map[string]any{"ip": e.IP, "jail": jail, "banned_at": e.Time})
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			h.Log.Warn("evento de ban não publicado", "err", err)
			return
		}
	}
}

func (h *Logs) filter(r *http.Request, p *validation.Problems) logstore.Filter {
	q := r.URL.Query()
	var f logstore.Filter
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		f.ServerID = strings.ToLower(v)
	}
	if v := q.Get("source"); v != "" {
		if _, ok := logs.Types[v]; !ok {
			p.Add("source", "deve ser nginx, fail2ban ou firewall")
		}
		f.Source = v
	}
	if v := q.Get("type"); v != "" {
		if len(v) > 32 || strings.IndexFunc(v, func(r rune) bool { return !(r == '_' || r >= 'a' && r <= 'z') }) >= 0 {
			p.Add("type", "valor inválido")
		}
		f.Type = v
	}
	switch v := q.Get("severity"); v {
	case "", logs.SevDebug, logs.SevInfo, logs.SevWarning, logs.SevError, logs.SevCritical:
		f.Severity = v
	default:
		p.Add("severity", "valor inválido")
	}
	if v := q.Get("ip"); v != "" {
		ip, ok := logs.NormalizeIP(v)
		if !ok {
			p.Add("ip", "IP inválido")
		}
		f.IP = ip
	}
	if v := q.Get("q"); v != "" {
		f.Q = p.Text("q", v, 1, 100)
	}
	now := h.now().UTC()
	from, to := parseTimeParam(p, r, "from"), parseTimeParam(p, r, "to")
	f.To, f.From = now.Add(time.Second), now.Add(-24*time.Hour)
	if to != nil {
		f.To = *to
	}
	if from != nil {
		f.From = *from
	} else if to != nil {
		f.From = f.To.Add(-24 * time.Hour)
	}
	switch {
	case !f.From.Before(f.To):
		p.Add("from", "deve ser anterior a 'to'")
	case f.To.Sub(f.From) > maxLogRange:
		p.Add("from", "o período máximo é de 31 dias")
	}
	return f
}

func (h *Logs) List(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var p validation.Problems
	page, per := pagination(r, &p)
	f := h.filter(r, &p)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	rows, total, err := h.Store.List(r.Context(), f, page, per)
	if err != nil {
		h.Log.Error("falha ao consultar logs", "err", err)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, h.withGeo(r.Context(), rows), newPageMeta(page, per, total))
}

func (h *Logs) Stats(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var p validation.Problems
	f := h.filter(r, &p)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	st, err := h.Store.Stats(r.Context(), f)
	if err != nil {
		h.Log.Error("falha ao agregar logs", "err", err)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, h.statsWithGeo(r.Context(), st), nil)
}

type logRowOut struct {
	logstore.Row
	Geo *ipintel.Info `json:"geo,omitempty"`
}

type ipCountOut struct {
	logstore.IPCount
	Geo *ipintel.Info `json:"geo,omitempty"`
}

// statsOut sobrepõe top_ips de logstore.Stats (o campo mais raso vence na serialização).
type statsOut struct {
	logstore.Stats
	TopIPs []ipCountOut `json:"top_ips"`
}

func (h *Logs) geo(ctx context.Context, ips []string) map[string]ipintel.Info {
	if h.Intel == nil || len(ips) == 0 {
		return nil
	}
	return h.Intel.Lookup(ctx, ips)
}

func (h *Logs) withGeo(ctx context.Context, rows []logstore.Row) []logRowOut {
	var ips []string
	for _, r := range rows {
		if r.IP != "" {
			ips = append(ips, r.IP)
		}
	}
	info := h.geo(ctx, ips)
	out := make([]logRowOut, len(rows))
	for i, r := range rows {
		out[i].Row = r
		if in, ok := info[r.IP]; ok {
			out[i].Geo = &in
		}
	}
	return out
}

func (h *Logs) statsWithGeo(ctx context.Context, st logstore.Stats) statsOut {
	ips := make([]string, 0, len(st.TopIPs))
	for _, c := range st.TopIPs {
		ips = append(ips, c.IP)
	}
	info := h.geo(ctx, ips)
	out := statsOut{Stats: st, TopIPs: make([]ipCountOut, len(st.TopIPs))}
	for i, c := range st.TopIPs {
		out.TopIPs[i].IPCount = c
		if in, ok := info[c.IP]; ok {
			out.TopIPs[i].Geo = &in
		}
	}
	return out
}

// recentBatches lembra lotes recentes para responder reenvios sem gravar (nem anunciar) de novo.
type recentBatches struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	m   map[string]time.Time
}

func newRecentBatches(ttl time.Duration, max int) *recentBatches {
	return &recentBatches{ttl: ttl, max: max, m: map[string]time.Time{}}
}

func (c *recentBatches) has(k string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[k]
	return ok && now.Sub(t) < c.ttl
}

func (c *recentBatches) add(k string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for key, t := range c.m {
			if now.Sub(t) >= c.ttl {
				delete(c.m, key)
			}
		}
		if len(c.m) >= c.max { // tudo recente: descarta tudo (a deduplicação do ClickHouse ainda protege)
			c.m = map[string]time.Time{}
		}
	}
	c.m[k] = now
}
