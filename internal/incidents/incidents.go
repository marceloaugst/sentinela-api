// Package incidents consulta incidentes e seus eventos.
//
// Relação com alertas: um incidente agrupa uma falha CONTÍNUA de uma combinação
// (servidor, regra[, serviço]) — há no máximo um incidente aberto por combinação. O alerta é a
// ocorrência avaliada pela regra e referencia o incidente; o reconhecimento é uma ação de um
// operador sobre o alerta e fica registrada como evento do incidente.
package incidents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("incidente não encontrado")

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

type Incident struct {
	ID              string     `json:"id"`
	ServerID        *string    `json:"server_id"`
	ServerName      *string    `json:"server_name"`
	RuleID          *string    `json:"rule_id"`
	RuleName        *string    `json:"rule_name"`
	ServiceID       *string    `json:"service_id"`
	ServiceName     *string    `json:"service_name"`
	Title           string     `json:"title"`
	Severity        string     `json:"severity"`
	Priority        int        `json:"priority"`         // 1 (P1, crítico) a 4 (P4, informativo)
	RecurrenceCount int        `json:"recurrence_count"` // incidentes iguais resolvidos nas 24 h anteriores à abertura
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	DurationSeconds int64      `json:"duration_seconds"` // incidente aberto: tempo decorrido até agora
}

type Event struct {
	ID        int64     `json:"id"`
	Type      string    `json:"event_type"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type AlertRef struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	Severity    string     `json:"severity"`
	Message     string     `json:"message"`
	TriggeredAt time.Time  `json:"triggered_at"`
	ResolvedAt  *time.Time `json:"resolved_at"`
}

type Detail struct {
	Incident
	Alerts []AlertRef `json:"alerts"`
}

const sel = `SELECT i.id, i.server_id, s.name, i.rule_id, r.name, i.service_id, ms.name, i.title, i.severity, i.priority, i.recurrence_count, i.status,
		i.started_at, i.resolved_at, extract(epoch FROM coalesce(i.resolved_at, now()) - i.started_at)::bigint
	FROM incidents i LEFT JOIN servers s ON s.id = i.server_id LEFT JOIN alert_rules r ON r.id = i.rule_id
	LEFT JOIN monitored_services ms ON ms.id = i.service_id`

func scan(row pgx.Row) (Incident, error) {
	var i Incident
	err := row.Scan(&i.ID, &i.ServerID, &i.ServerName, &i.RuleID, &i.RuleName, &i.ServiceID, &i.ServiceName, &i.Title,
		&i.Severity, &i.Priority, &i.RecurrenceCount, &i.Status, &i.StartedAt, &i.ResolvedAt, &i.DurationSeconds)
	return i, err
}

type ListParams struct {
	Page, PerPage int
	Status        string
	Severity      string
	Priority      int
	ServerID      string
	From, To      *time.Time // filtro por started_at
}

func (r *Repository) List(ctx context.Context, p ListParams) ([]Incident, int, error) {
	where := []string{"true"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.Status != "" {
		add("i.status = ?", p.Status)
	}
	if p.Severity != "" {
		add("i.severity = ?", p.Severity)
	}
	if p.Priority != 0 {
		add("i.priority = ?", p.Priority)
	}
	if p.ServerID != "" {
		add("i.server_id = ?", p.ServerID)
	}
	if p.From != nil {
		add("i.started_at >= ?", *p.From)
	}
	if p.To != nil {
		add("i.started_at < ?", *p.To)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM incidents i WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`%s WHERE %s ORDER BY i.started_at DESC, i.id LIMIT $%d OFFSET $%d`,
		sel, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		i, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, i)
	}
	return out, total, rows.Err()
}

func (r *Repository) Get(ctx context.Context, id string) (Detail, error) {
	i, err := scan(r.pool.QueryRow(ctx, sel+` WHERE i.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Detail{}, ErrNotFound
	}
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Incident: i, Alerts: []AlertRef{}}
	rows, err := r.pool.Query(ctx, `SELECT id, status, severity, message, triggered_at, resolved_at FROM alerts
		WHERE incident_id = $1 ORDER BY triggered_at, id`, id)
	if err != nil {
		return Detail{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var a AlertRef
		if err := rows.Scan(&a.ID, &a.Status, &a.Severity, &a.Message, &a.TriggeredAt, &a.ResolvedAt); err != nil {
			return Detail{}, err
		}
		d.Alerts = append(d.Alerts, a)
	}
	return d, rows.Err()
}

// Events devolve a linha do tempo do incidente em ordem cronológica.
func (r *Repository) Events(ctx context.Context, id string) ([]Event, error) {
	var ok bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM incidents WHERE id = $1)`, id).Scan(&ok); err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	rows, err := r.pool.Query(ctx, `SELECT id, event_type, message, created_at FROM incident_events
		WHERE incident_id = $1 ORDER BY created_at, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Type, &e.Message, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
