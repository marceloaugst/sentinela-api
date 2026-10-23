package dockerhost

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// Replace grava o retrato do agente. Um relatório mais antigo que o gravado é ignorado (reenvio fora de ordem).
func (r *Repository) Replace(ctx context.Context, serverID string, rep Report) error {
	raw, err := json.Marshal(rep.Containers)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO docker_snapshots (server_id, status, message, checked_at, containers)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (server_id) DO UPDATE SET status = EXCLUDED.status, message = EXCLUDED.message,
			checked_at = EXCLUDED.checked_at, containers = EXCLUDED.containers
		WHERE docker_snapshots.checked_at <= EXCLUDED.checked_at`,
		serverID, rep.Status, rep.Message, rep.CheckedAt, raw)
	return err
}

// Get devolve o último retrato do servidor; nil se o agente ainda não enviou nenhum.
func (r *Repository) Get(ctx context.Context, serverID string) (*Report, error) {
	var rep Report
	var raw []byte
	err := r.pool.QueryRow(ctx, `SELECT status, message, checked_at, containers FROM docker_snapshots WHERE server_id = $1`,
		serverID).Scan(&rep.Status, &rep.Message, &rep.CheckedAt, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &rep.Containers); err != nil {
		return nil, err
	}
	if rep.Containers == nil {
		rep.Containers = []Container{}
	}
	for i := range rep.Containers {
		rep.Containers[i].Actions = Allowed(rep.Containers[i].State)
	}
	return &rep, nil
}
