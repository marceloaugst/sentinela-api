package procs

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
	raw, err := json.Marshal(rep.Processes)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO process_snapshots (server_id, checked_at, cpus, memory_total_bytes, total, processes)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (server_id) DO UPDATE SET checked_at = EXCLUDED.checked_at, cpus = EXCLUDED.cpus,
			memory_total_bytes = EXCLUDED.memory_total_bytes, total = EXCLUDED.total, processes = EXCLUDED.processes
		WHERE process_snapshots.checked_at <= EXCLUDED.checked_at`,
		serverID, rep.CheckedAt, rep.CPUs, rep.MemoryTotalBytes, rep.Total, raw)
	return err
}

// Get devolve o último retrato do servidor, já com os campos calculados; nil se o agente ainda não enviou nenhum.
func (r *Repository) Get(ctx context.Context, serverID string) (*Report, error) {
	var rep Report
	var raw []byte
	err := r.pool.QueryRow(ctx, `SELECT checked_at, cpus, memory_total_bytes, total, processes FROM process_snapshots WHERE server_id = $1`,
		serverID).Scan(&rep.CheckedAt, &rep.CPUs, &rep.MemoryTotalBytes, &rep.Total, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &rep.Processes); err != nil {
		return nil, err
	}
	if rep.Processes == nil {
		rep.Processes = []Process{}
	}
	rep.Decorate()
	return &rep, nil
}
