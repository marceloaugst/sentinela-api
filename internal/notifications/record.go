package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("notificação não encontrada")

// Record grava a notificação no PostgreSQL (tabela notifications), NA TRANSAÇÃO do chamador. É o registro
// permanente: existe mesmo sem canal externo configurado e não depende de a entrega ter funcionado.
// Todo alerta (qualquer prioridade) e todo IP banido passam por aqui.
func Record(ctx context.Context, tx pgx.Tx, p Payload) error {
	var kind, title string
	priority, severity := p.Priority, p.Severity
	subject := p.RuleName
	if p.ServiceName != "" {
		subject += " — " + p.ServiceName
	}
	switch p.Kind {
	case KindTriggered:
		kind, title = "alert_triggered", fmt.Sprintf("%s — %s", subject, p.ServerName)
		if priority < 1 || priority > 4 {
			priority = map[string]int{"critical": 1, "warning": 3}[severity]
			if priority == 0 {
				priority = 4
			}
		}
	case KindResolved:
		kind, title = "alert_resolved", fmt.Sprintf("Recuperado: %s — %s", subject, p.ServerName)
		priority, severity = 4, "info" // recuperação é informativa (P4)
	case KindIPBanned:
		kind, title = "ip_banned", fmt.Sprintf("IP banido: %s — %s", p.RuleName, p.ServerName)
		priority, severity = 3, "warning"
	default:
		return nil // testes de canal não são registrados
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notifications (kind, priority, severity, server_id, alert_id, incident_id, title, message, data, created_at)
		VALUES ($1,$2,$3,NULLIF($4,'')::uuid,NULLIF($5,'')::uuid,NULLIF($6,'')::uuid,$7,$8,$9,$10)
		ON CONFLICT (kind, alert_id) WHERE alert_id IS NOT NULL DO NOTHING`,
		kind, priority, severity, p.ServerID, p.AlertID, p.IncidentID, title, p.Message, data, p.At)
	return err
}

// Notification é um registro de notificação para o painel.
type Notification struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	Priority   int             `json:"priority"`
	Severity   string          `json:"severity"`
	ServerID   *string         `json:"server_id"`
	ServerName *string         `json:"server_name"`
	AlertID    *string         `json:"alert_id"`
	IncidentID *string         `json:"incident_id"`
	Title      string          `json:"title"`
	Message    string          `json:"message"`
	Data       json.RawMessage `json:"data"`
	CreatedAt  time.Time       `json:"created_at"`
	ReadAt     *time.Time      `json:"read_at"`
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

type ListParams struct {
	Page, PerPage int
	Kind          string
	Priority      int
	ServerID      string
	Unread        bool
	From, To      *time.Time
}

const notifSelect = `SELECT n.id, n.kind, n.priority, n.severity, n.server_id::text, s.name, n.alert_id::text, n.incident_id::text,
		n.title, n.message, n.data, n.created_at, n.read_at
	FROM notifications n LEFT JOIN servers s ON s.id = n.server_id`

func (st *Store) List(ctx context.Context, p ListParams) ([]Notification, int, error) {
	where := []string{"true"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.Kind != "" {
		add("n.kind = ?", p.Kind)
	}
	if p.Priority != 0 {
		add("n.priority = ?", p.Priority)
	}
	if p.ServerID != "" {
		add("n.server_id = ?", p.ServerID)
	}
	if p.Unread {
		where = append(where, "n.read_at IS NULL")
	}
	if p.From != nil {
		add("n.created_at >= ?", *p.From)
	}
	if p.To != nil {
		add("n.created_at < ?", *p.To)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := st.pool.QueryRow(ctx, "SELECT count(*) FROM notifications n WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := st.pool.Query(ctx, fmt.Sprintf(`%s WHERE %s ORDER BY n.created_at DESC, n.id DESC LIMIT $%d OFFSET $%d`,
		notifSelect, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Notification{}
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

func scanNotification(row pgx.Row) (Notification, error) {
	var n Notification
	err := row.Scan(&n.ID, &n.Kind, &n.Priority, &n.Severity, &n.ServerID, &n.ServerName, &n.AlertID, &n.IncidentID,
		&n.Title, &n.Message, &n.Data, &n.CreatedAt, &n.ReadAt)
	return n, err
}

// UnreadCount devolve quantas notificações ainda não foram lidas.
func (st *Store) UnreadCount(ctx context.Context) (int, error) {
	var n int
	err := st.pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE read_at IS NULL`).Scan(&n)
	return n, err
}

// MarkRead marca uma notificação como lida (idempotente). userID vazio = chave administrativa.
func (st *Store) MarkRead(ctx context.Context, id int64, userID string) (Notification, error) {
	tag, err := st.pool.Exec(ctx, `UPDATE notifications SET read_at = COALESCE(read_at, now()),
		read_by = CASE WHEN read_at IS NULL THEN NULLIF($2,'')::uuid ELSE read_by END WHERE id = $1`, id, userID)
	if err != nil {
		return Notification{}, err
	}
	if tag.RowsAffected() == 0 {
		return Notification{}, ErrNotFound
	}
	return scanNotification(st.pool.QueryRow(ctx, notifSelect+` WHERE n.id = $1`, id))
}

// MarkAllRead marca todas como lidas e devolve quantas mudaram.
func (st *Store) MarkAllRead(ctx context.Context, userID string) (int64, error) {
	tag, err := st.pool.Exec(ctx, `UPDATE notifications SET read_at = now(), read_by = NULLIF($1,'')::uuid WHERE read_at IS NULL`, userID)
	return tag.RowsAffected(), err
}
