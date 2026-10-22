package discovery

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// Replace grava o retrato enviado pelo agente: atualiza os itens presentes e remove os que sumiram
// do relatório. Um relatório mais antigo que o já gravado é ignorado (reenvio fora de ordem).
func (r *Repository) Replace(ctx context.Context, serverID string, rep Report) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serializa relatórios do mesmo servidor e descarta o que já está desatualizado: um reenvio
	// fora de ordem não pode ressuscitar itens que o retrato mais novo removeu.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, serverID); err != nil {
		return err
	}
	var newest *time.Time
	if err := tx.QueryRow(ctx, `SELECT max(checked_at) FROM service_discovery WHERE server_id = $1`, serverID).Scan(&newest); err != nil {
		return err
	}
	if newest != nil && newest.After(rep.CheckedAt) {
		return nil
	}

	keys := make([]string, 0, len(rep.Services))
	for _, f := range rep.Services {
		keys = append(keys, f.Key)
		if _, err := tx.Exec(ctx, `INSERT INTO service_discovery (server_id, key, status, source, unit, checked_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (server_id, key) DO UPDATE SET
				status = EXCLUDED.status, source = EXCLUDED.source, unit = EXCLUDED.unit, checked_at = EXCLUDED.checked_at,
				status_changed_at = CASE WHEN service_discovery.status <> EXCLUDED.status THEN now()
				                         ELSE service_discovery.status_changed_at END`,
			serverID, f.Key, f.Status, f.Source, f.Unit, rep.CheckedAt); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM service_discovery WHERE server_id = $1 AND NOT (key = ANY($2))`,
		serverID, keys); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// List devolve os itens do servidor na ordem do catálogo, com a ação recomendada.
func (r *Repository) List(ctx context.Context, serverID string) ([]Item, error) {
	rows, err := r.pool.Query(ctx, `SELECT key, status, source, unit, checked_at, status_changed_at
		FROM service_discovery WHERE server_id = $1`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKey := map[string]Item{}
	for rows.Next() {
		var key, status, source, unit string
		var checked, changed time.Time
		if err := rows.Scan(&key, &status, &source, &unit, &checked, &changed); err != nil {
			return nil, err
		}
		byKey[key] = NewItem(key, status, source, unit, checked, &changed)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(byKey))
	for _, spec := range Catalog {
		if it, ok := byKey[spec.Key]; ok {
			out = append(out, it)
		}
	}
	return out, nil
}
