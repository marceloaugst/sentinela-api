// Package audit grava ações administrativas relevantes em audit_logs.
package audit

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Execer é satisfeito por pgx.Tx e *pgxpool.Pool, permitindo auditar na mesma transação.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Context identifica quem agiu: Actor é o rótulo legível (e-mail do usuário, "api_key" ou "sistema") e
// UserID, quando houver, preenche audit_logs.actor_user_id.
type Context struct {
	Actor  string
	UserID string
	IP     string
}

var sensitive = []string{"token", "password", "secret", "key", "hash"}

// Redact substitui valores de chaves que parecem segredos, sem mutar a entrada.
func Redact(meta map[string]any) map[string]any {
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		lk := strings.ToLower(k)
		redacted := false
		for _, s := range sensitive {
			if strings.Contains(lk, s) {
				redacted = true
				break
			}
		}
		if redacted {
			out[k] = "[redacted]"
		} else {
			out[k] = v
		}
	}
	return out
}

func Write(ctx context.Context, ex Execer, ac Context, action, resourceType, resourceID string, meta map[string]any) error {
	m := Redact(meta)
	m["actor"] = ac.Actor
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var ip *string
	if parsed := net.ParseIP(ac.IP); parsed != nil {
		s := parsed.String()
		ip = &s
	}
	_, err = ex.Exec(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, metadata, ip, actor_user_id)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, NULLIF($6, '')::uuid)`, action, resourceType, resourceID, raw, ip, ac.UserID)
	return err
}
