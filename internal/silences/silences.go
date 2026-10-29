// Package silences implementa silenciamentos e janelas de manutenção de alertas. Enquanto uma janela está ativa, os
// alertas que casam com o escopo (servidor e/ou regra) continuam sendo avaliados e registrados, mas não geram
// notificação externa (Telegram). Escopo vazio = todos.
package silences

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/validation"
)

const (
	KindSilence     = "silence"
	KindMaintenance = "maintenance"

	StatusActive    = "active"
	StatusScheduled = "scheduled"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"

	// MaxDuration limita uma janela; MaxLeadTime, o quanto no futuro ela pode começar.
	MaxDuration = 30 * 24 * time.Hour
	MaxLeadTime = 90 * 24 * time.Hour
)

var (
	ErrNotFound      = errors.New("silenciamento não encontrado")
	ErrUnknownServer = errors.New("servidor não encontrado")
	ErrUnknownRule   = errors.New("regra não encontrada")

	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

type Silence struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason"`
	ServerID    *string    `json:"server_id"`
	ServerName  *string    `json:"server_name"`
	RuleID      *string    `json:"rule_id"`
	RuleName    *string    `json:"rule_name"`
	StartsAt    time.Time  `json:"starts_at"`
	EndsAt      time.Time  `json:"ends_at"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	CancelledAt *time.Time `json:"cancelled_at"`
	CancelledBy *string    `json:"cancelled_by"`
}

type CreateInput struct {
	Kind            string     `json:"kind"`
	Reason          string     `json:"reason"`
	ServerID        *string    `json:"server_id"`
	RuleID          *string    `json:"rule_id"`
	StartsAt        *time.Time `json:"starts_at"`
	EndsAt          *time.Time `json:"ends_at"`
	DurationMinutes *int       `json:"duration_minutes"`

	// preenchidos por Validate
	starts, ends time.Time
}

// Validate confere e normaliza a entrada. now é o horário atual. Informe ends_at OU duration_minutes; starts_at é opcional (padrão: agora).
func (in *CreateInput) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	if in.Kind == "" {
		in.Kind = KindSilence
	}
	if in.Kind != KindSilence && in.Kind != KindMaintenance {
		p.Add("kind", "deve ser silence ou maintenance")
	}
	in.Reason = p.Text("reason", in.Reason, 1, 300)
	for field, v := range map[string]**string{"server_id": &in.ServerID, "rule_id": &in.RuleID} {
		if *v == nil {
			continue
		}
		s := strings.ToLower(strings.TrimSpace(**v))
		if !uuidRe.MatchString(s) {
			p.Add(field, "deve ser um UUID")
		}
		*v = &s
	}

	in.starts = now
	if in.StartsAt != nil {
		in.starts = in.StartsAt.UTC()
	}
	switch {
	case in.EndsAt != nil && in.DurationMinutes != nil:
		p.Add("ends_at", "informe ends_at ou duration_minutes, não os dois")
	case in.EndsAt != nil:
		in.ends = in.EndsAt.UTC()
	case in.DurationMinutes != nil:
		if *in.DurationMinutes < 1 {
			p.Add("duration_minutes", "deve ser >= 1")
		} else if time.Duration(*in.DurationMinutes)*time.Minute > MaxDuration {
			p.Add("duration_minutes", "excede o máximo de 30 dias")
		} else {
			in.ends = in.starts.Add(time.Duration(*in.DurationMinutes) * time.Minute)
		}
	default:
		p.Add("ends_at", "informe ends_at ou duration_minutes")
	}
	if len(p) > 0 {
		return p
	}
	switch {
	case !in.ends.After(in.starts):
		p.Add("ends_at", "deve ser posterior ao início")
	case !in.ends.After(now):
		p.Add("ends_at", "deve estar no futuro")
	case in.ends.Sub(in.starts) > MaxDuration:
		p.Add("ends_at", "a janela excede o máximo de 30 dias")
	case in.starts.After(now.Add(MaxLeadTime)):
		p.Add("starts_at", "começa daqui a mais de 90 dias")
	}
	return p
}

type Repository struct {
	pool *pgxpool.Pool
	Now  func() time.Time // injetável em testes
}

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

func (r *Repository) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// O status é calculado a partir de $1 (agora), nunca guardado.
const selectSQL = `SELECT x.id, x.kind,
		CASE WHEN x.cancelled_at IS NOT NULL THEN 'cancelled' WHEN x.ends_at <= $1 THEN 'expired'
		     WHEN x.starts_at > $1 THEN 'scheduled' ELSE 'active' END AS status,
		x.reason, x.server_id::text, s.name, x.rule_id::text, r.name, x.starts_at, x.ends_at,
		x.created_by_label, x.created_at, x.cancelled_at, x.cancelled_by_label
	FROM alert_silences x
	LEFT JOIN servers s ON s.id = x.server_id
	LEFT JOIN alert_rules r ON r.id = x.rule_id`

func scan(row pgx.Row) (Silence, error) {
	var s Silence
	err := row.Scan(&s.ID, &s.Kind, &s.Status, &s.Reason, &s.ServerID, &s.ServerName, &s.RuleID, &s.RuleName, &s.StartsAt, &s.EndsAt,
		&s.CreatedBy, &s.CreatedAt, &s.CancelledAt, &s.CancelledBy)
	return s, err
}

func (r *Repository) Create(ctx context.Context, ac audit.Context, in CreateInput) (Silence, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Silence{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if in.ServerID != nil {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM servers WHERE id = $1 AND deleted_at IS NULL)`, *in.ServerID).Scan(&ok); err != nil {
			return Silence{}, err
		}
		if !ok {
			return Silence{}, ErrUnknownServer
		}
	}
	if in.RuleID != nil {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM alert_rules WHERE id = $1 AND deleted_at IS NULL)`, *in.RuleID).Scan(&ok); err != nil {
			return Silence{}, err
		}
		if !ok {
			return Silence{}, ErrUnknownRule
		}
	}
	now := r.now()
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO alert_silences (kind, reason, server_id, rule_id, starts_at, ends_at, created_by, created_by_label, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,'')::uuid,$8,$9) RETURNING id`,
		in.Kind, in.Reason, in.ServerID, in.RuleID, in.starts, in.ends, ac.UserID, ac.Actor, now).Scan(&id); err != nil {
		return Silence{}, err
	}
	if err := audit.Write(ctx, tx, ac, "silence.create", "silence", id, map[string]any{
		"kind": in.Kind, "reason": in.Reason, "server_id": in.ServerID, "rule_id": in.RuleID,
		"starts_at": in.starts, "ends_at": in.ends,
	}); err != nil {
		return Silence{}, err
	}
	out, err := scan(tx.QueryRow(ctx, selectSQL+` WHERE x.id = $2`, now, id))
	if err != nil {
		return Silence{}, err
	}
	return out, tx.Commit(ctx)
}

func (r *Repository) Get(ctx context.Context, id string) (Silence, error) {
	s, err := scan(r.pool.QueryRow(ctx, selectSQL+` WHERE x.id = $2`, r.now(), id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Silence{}, ErrNotFound
	}
	return s, err
}

type ListParams struct {
	Page, PerPage int
	Status        string // active | scheduled | ended (expirado ou cancelado) | vazio = todos
	ServerID      string
}

func (r *Repository) List(ctx context.Context, p ListParams) ([]Silence, int, error) {
	now := r.now()
	where := []string{"true"}
	args := []any{now}
	switch p.Status {
	case StatusActive:
		where = append(where, "x.cancelled_at IS NULL AND x.starts_at <= $1 AND x.ends_at > $1")
	case StatusScheduled:
		where = append(where, "x.cancelled_at IS NULL AND x.starts_at > $1")
	case "ended":
		where = append(where, "(x.cancelled_at IS NOT NULL OR x.ends_at <= $1)")
	}
	if p.ServerID != "" {
		args = append(args, p.ServerID)
		// uma janela sem servidor vale para todos
		where = append(where, fmt.Sprintf("(x.server_id = $%d OR x.server_id IS NULL)", len(args)))
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM alert_silences x WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`%s WHERE %s ORDER BY x.starts_at DESC, x.id LIMIT $%d OFFSET $%d`, selectSQL, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Silence{}
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// Cancel encerra a janela agora (ou a descarta, se ainda não começou). Idempotente: já encerrada/cancelada devolve o registro como está.
func (r *Repository) Cancel(ctx context.Context, ac audit.Context, id string) (Silence, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Silence{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	now := r.now()
	tag, err := tx.Exec(ctx, `UPDATE alert_silences SET cancelled_at = $2, cancelled_by_label = $3
		WHERE id = $1 AND cancelled_at IS NULL AND ends_at > $2`, id, now, ac.Actor)
	if err != nil {
		return Silence{}, err
	}
	if tag.RowsAffected() == 1 {
		if err := audit.Write(ctx, tx, ac, "silence.cancel", "silence", id, nil); err != nil {
			return Silence{}, err
		}
	}
	out, err := scan(tx.QueryRow(ctx, selectSQL+` WHERE x.id = $2`, now, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Silence{}, ErrNotFound
	}
	if err != nil {
		return Silence{}, err
	}
	return out, tx.Commit(ctx)
}

// Querier é satisfeito por pgx.Tx e *pgxpool.Pool.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ActiveFor devolve a janela ativa que cobre o par (servidor, regra), ou nil. Havendo várias, a que termina por último.
func ActiveFor(ctx context.Context, q Querier, serverID, ruleID string, now time.Time) (*Silence, error) {
	s, err := scan(q.QueryRow(ctx, selectSQL+` WHERE x.cancelled_at IS NULL AND x.starts_at <= $1 AND x.ends_at > $1
		AND (x.server_id IS NULL OR x.server_id = $2) AND (x.rule_id IS NULL OR x.rule_id = $3)
		ORDER BY x.ends_at DESC LIMIT 1`, now, serverID, ruleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}
