package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Entry struct {
	ID           int64          `json:"id"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   *string        `json:"resource_id"`
	Actor        string         `json:"actor"`
	ActorUserID  *string        `json:"actor_user_id"`
	IP           *string        `json:"ip"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    time.Time      `json:"created_at"`
}

type ListParams struct {
	Page, PerPage int
	Action        string // igualdade, ou prefixo quando termina com "."
	ResourceType  string
	ResourceID    string
	ActorUserID   string
	From, To      *time.Time
}

// List consulta a trilha de auditoria (mais recentes primeiro).
func List(ctx context.Context, pool *pgxpool.Pool, p ListParams) ([]Entry, int, error) {
	where := []string{"true"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.Action != "" {
		if strings.HasSuffix(p.Action, ".") {
			add("action LIKE ?", escape(p.Action)+"%")
		} else {
			add("action = ?", p.Action)
		}
	}
	if p.ResourceType != "" {
		add("resource_type = ?", p.ResourceType)
	}
	if p.ResourceID != "" {
		add("resource_id = ?", p.ResourceID)
	}
	if p.ActorUserID != "" {
		add("actor_user_id = ?::uuid", p.ActorUserID)
	}
	if p.From != nil {
		add("created_at >= ?", *p.From)
	}
	if p.To != nil {
		add("created_at < ?", *p.To)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := pool.Query(ctx, fmt.Sprintf(`SELECT id, action, resource_type, resource_id, COALESCE(metadata->>'actor', ''),
			actor_user_id::text, host(ip), metadata, created_at
		FROM audit_logs WHERE %s ORDER BY id DESC LIMIT $%d OFFSET $%d`, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Action, &e.ResourceType, &e.ResourceID, &e.Actor, &e.ActorUserID, &e.IP, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func escape(s string) string { return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) }

// Purge remove registros anteriores a before (política de retenção da auditoria). Devolve quantos.
func Purge(ctx context.Context, pool *pgxpool.Pool, before time.Time) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, before)
	return tag.RowsAffected(), err
}
