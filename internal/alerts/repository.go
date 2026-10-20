package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/events"
)

type Repository struct {
	pool *pgxpool.Pool
	// Now é injetável em testes; nil usa o relógio real.
	Now func() time.Time
}

func (r *Repository) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const ruleCols = `id, name, metric_name, operator, threshold, severity, duration_seconds, recovery_seconds, server_id, is_enabled, created_at, updated_at`

func scanRule(row pgx.Row) (Rule, error) {
	var r Rule
	err := row.Scan(&r.ID, &r.Name, &r.MetricName, &r.Operator, &r.Threshold, &r.Severity, &r.DurationSeconds,
		&r.RecoverySeconds, &r.ServerID, &r.IsEnabled, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

func (r *Repository) serverExists(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM servers WHERE id = $1 AND deleted_at IS NULL)`, id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrServerNotFound
	}
	return nil
}

func (r *Repository) CreateRule(ctx context.Context, ac audit.Context, in Rule) (Rule, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Rule{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if in.ServerID != nil {
		if err := r.serverExists(ctx, tx, *in.ServerID); err != nil {
			return Rule{}, err
		}
	}
	out, err := scanRule(tx.QueryRow(ctx, `INSERT INTO alert_rules (name, metric_name, operator, threshold, severity,
			duration_seconds, recovery_seconds, server_id, is_enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+ruleCols,
		in.Name, in.MetricName, in.Operator, in.Threshold, in.Severity, in.DurationSeconds, in.RecoverySeconds, in.ServerID, in.IsEnabled))
	if err != nil {
		return Rule{}, err
	}
	if err := audit.Write(ctx, tx, ac, "alert_rule.create", "alert_rule", out.ID, ruleMeta(out)); err != nil {
		return Rule{}, err
	}
	return out, tx.Commit(ctx)
}

func ruleMeta(r Rule) map[string]any {
	m := map[string]any{"name": r.Name, "metric": r.MetricName, "operator": r.Operator, "threshold": r.Threshold,
		"severity": r.Severity, "duration_seconds": r.DurationSeconds, "recovery_seconds": r.RecoverySeconds, "enabled": r.IsEnabled}
	if r.ServerID != nil {
		m["server_id"] = *r.ServerID
	}
	return m
}

func (r *Repository) GetRule(ctx context.Context, id string) (Rule, error) {
	out, err := scanRule(r.pool.QueryRow(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE id = $1 AND deleted_at IS NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrRuleNotFound
	}
	return out, err
}

// UpdateRule grava a regra já validada/mesclada (ver UpdateRuleInput.Validate).
func (r *Repository) UpdateRule(ctx context.Context, ac audit.Context, next Rule) (Rule, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Rule{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if next.ServerID != nil {
		if err := r.serverExists(ctx, tx, *next.ServerID); err != nil {
			return Rule{}, err
		}
	}
	out, err := scanRule(tx.QueryRow(ctx, `UPDATE alert_rules SET name=$2, metric_name=$3, operator=$4, threshold=$5, severity=$6,
			duration_seconds=$7, recovery_seconds=$8, server_id=$9, is_enabled=$10, updated_at=now()
		WHERE id = $1 AND deleted_at IS NULL RETURNING `+ruleCols,
		next.ID, next.Name, next.MetricName, next.Operator, next.Threshold, next.Severity, next.DurationSeconds,
		next.RecoverySeconds, next.ServerID, next.IsEnabled))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrRuleNotFound
	}
	if err != nil {
		return Rule{}, err
	}
	if err := audit.Write(ctx, tx, ac, "alert_rule.update", "alert_rule", out.ID, ruleMeta(out)); err != nil {
		return Rule{}, err
	}
	return out, tx.Commit(ctx)
}

// DeleteRule faz exclusão lógica; o avaliador resolve os alertas ativos da regra (rule_deleted)
// no próximo ciclo e o histórico permanece.
func (r *Repository) DeleteRule(ctx context.Context, ac audit.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE alert_rules SET deleted_at = now(), is_enabled = false, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	if err := audit.Write(ctx, tx, ac, "alert_rule.delete", "alert_rule", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type RuleListParams struct {
	Page, PerPage int
	MetricName    string
	Severity      string
	ServerID      string
	Enabled       *bool
}

func (r *Repository) ListRules(ctx context.Context, p RuleListParams) ([]Rule, int, error) {
	where := []string{"deleted_at IS NULL"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.MetricName != "" {
		add("metric_name = ?", p.MetricName)
	}
	if p.Severity != "" {
		add("severity = ?", p.Severity)
	}
	if p.ServerID != "" {
		add("server_id = ?", p.ServerID)
	}
	if p.Enabled != nil {
		add("is_enabled = ?", *p.Enabled)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM alert_rules WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM alert_rules WHERE %s ORDER BY lower(name), id LIMIT $%d OFFSET $%d`,
		ruleCols, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		x, err := scanRule(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, x)
	}
	return out, total, rows.Err()
}

// ---- alertas ----

type Alert struct {
	ID              string     `json:"id"`
	RuleID          string     `json:"rule_id"`
	RuleName        string     `json:"rule_name"`
	ServerID        string     `json:"server_id"`
	ServerName      string     `json:"server_name"`
	ServiceID       *string    `json:"service_id"`
	ServiceName     *string    `json:"service_name"`
	IncidentID      *string    `json:"incident_id"`
	Status          string     `json:"status"`
	Severity        string     `json:"severity"`
	Message         string     `json:"message"`
	Value           *float64   `json:"value"`
	TriggeredAt     time.Time  `json:"triggered_at"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at"`
	AcknowledgedBy  *string    `json:"acknowledged_by"` // id do usuário; nulo quando reconhecido pela chave de API
	ResolvedAt      *time.Time `json:"resolved_at"`
	ResolvedReason  *string    `json:"resolved_reason"`
	LastEvaluatedAt time.Time  `json:"last_evaluated_at"`
}

const alertSelect = `SELECT a.id, a.rule_id, r.name, a.server_id, s.name, a.service_id, ms.name, a.incident_id, a.status, a.severity,
		a.message, a.value, a.triggered_at, a.acknowledged_at, a.acknowledged_by::text, a.resolved_at, a.resolved_reason, a.last_evaluated_at
	FROM alerts a JOIN alert_rules r ON r.id = a.rule_id JOIN servers s ON s.id = a.server_id
	LEFT JOIN monitored_services ms ON ms.id = a.service_id`

func scanAlert(row pgx.Row) (Alert, error) {
	var a Alert
	err := row.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.ServerID, &a.ServerName, &a.ServiceID, &a.ServiceName, &a.IncidentID,
		&a.Status, &a.Severity, &a.Message, &a.Value, &a.TriggeredAt, &a.AcknowledgedAt, &a.AcknowledgedBy, &a.ResolvedAt,
		&a.ResolvedReason, &a.LastEvaluatedAt)
	return a, err
}

func (r *Repository) GetAlert(ctx context.Context, id string) (Alert, error) {
	a, err := scanAlert(r.pool.QueryRow(ctx, alertSelect+` WHERE a.id = $1 AND a.status <> 'pending'`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, ErrAlertNotFound
	}
	return a, err
}

type AlertListParams struct {
	Page, PerPage int
	Status        string // "" = firing+acknowledged+resolved; "active"; ou um estado
	Severity      string
	ServerID      string
	RuleID        string
	From, To      *time.Time
}

func (r *Repository) ListAlerts(ctx context.Context, p AlertListParams) ([]Alert, int, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	switch p.Status {
	case "":
		where = append(where, "a.status <> 'pending'") // pending ainda não é um alerta
	case "active":
		where = append(where, "a.status IN ('firing','acknowledged')")
	default:
		add("a.status = ?", p.Status)
	}
	if p.Severity != "" {
		add("a.severity = ?", p.Severity)
	}
	if p.ServerID != "" {
		add("a.server_id = ?", p.ServerID)
	}
	if p.RuleID != "" {
		add("a.rule_id = ?", p.RuleID)
	}
	if p.From != nil {
		add("a.triggered_at >= ?", *p.From)
	}
	if p.To != nil {
		add("a.triggered_at < ?", *p.To)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM alerts a WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`%s WHERE %s ORDER BY a.triggered_at DESC, a.id LIMIT $%d OFFSET $%d`,
		alertSelect, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func lockAlert(ctx context.Context, tx pgx.Tx, id string) (alertRow, error) {
	a, err := scanAlertRow(tx.QueryRow(ctx, `SELECT id, rule_id, server_id, service_id, incident_id, status, severity, message, pending_since, recovering_since
		FROM alerts WHERE id = $1 AND status <> 'pending' FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return alertRow{}, ErrAlertNotFound
	}
	return a, err
}

// Acknowledge reconhece um alerta ativo. É idempotente: reconhecer de novo não altera nada.
// Alertas já resolvidos não podem ser reconhecidos.
func (r *Repository) Acknowledge(ctx context.Context, ac audit.Context, id, note string) (Alert, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	a, err := lockAlert(ctx, tx, id)
	if err != nil {
		return Alert{}, err
	}
	switch a.Status {
	case StatusResolved:
		return Alert{}, ErrInvalidState
	case StatusFiring:
		now := r.now()
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'acknowledged', acknowledged_at = $2, acknowledged_by = NULLIF($3, '')::uuid WHERE id = $1`, id, now, ac.UserID); err != nil {
			return Alert{}, err
		}
		if a.IncidentID != nil {
			msg := "Alerta reconhecido por " + ac.Actor
			if note != "" {
				msg += ": " + note
			}
			if err := addEvent(ctx, tx, *a.IncidentID, "acknowledged", msg, now); err != nil {
				return Alert{}, err
			}
		}
		if err := audit.Write(ctx, tx, ac, "alert.acknowledge", "alert", id, map[string]any{"note": note}); err != nil {
			return Alert{}, err
		}
		// evento por ÚLTIMO (ver events.Publish); a nota do operador não é publicada
		full, err := scanAlert(tx.QueryRow(ctx, alertSelect+` WHERE a.id = $1`, id))
		if err != nil {
			return Alert{}, err
		}
		ev := alertEvent{AlertID: full.ID, ServerID: full.ServerID, ServerName: full.ServerName, ServiceID: full.ServiceID,
			RuleID: full.RuleID, RuleName: full.RuleName, Severity: full.Severity, Status: StatusAcknowledged, Message: full.Message, At: now}
		if full.ServiceName != nil {
			ev.ServiceName = *full.ServiceName
		}
		if full.IncidentID != nil {
			ev.IncidentID = *full.IncidentID
		}
		if err := events.Publish(ctx, tx, events.TypeAlertAcknowledged, full.ServerID, ev); err != nil {
			return Alert{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Alert{}, err
	}
	return r.GetAlert(ctx, id)
}

// ResolveManual resolve um alerta ativo (e seu incidente). Se a condição ainda existir, o avaliador
// abrirá um novo alerta quando ela voltar a ser avaliada como verdadeira (após duration_seconds).
func (r *Repository) ResolveManual(ctx context.Context, ac audit.Context, id string) (Alert, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	a, err := lockAlert(ctx, tx, id)
	if err != nil {
		return Alert{}, err
	}
	if a.Status == StatusResolved {
		return Alert{}, ErrInvalidState
	}
	if err := resolve(ctx, tx, a, ReasonManual, ac.Actor, r.now()); err != nil {
		return Alert{}, err
	}
	if err := audit.Write(ctx, tx, ac, "alert.resolve", "alert", id, nil); err != nil {
		return Alert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Alert{}, err
	}
	return r.GetAlert(ctx, id)
}
