package metrics

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// touchServer registra a comunicação válida. last_seen_at usa o relógio do banco
// (horário de recebimento), nunca o horário informado pelo agente. Campos de
// inventário vazios não sobrescrevem valores já conhecidos.
func touchServer(ctx context.Context, tx pgx.Tx, serverID, agentVersion string, h Host) error {
	_, err := tx.Exec(ctx, `UPDATE servers SET
			last_seen_at = now(),
			agent_version = NULLIF($2, ''),
			operating_system = COALESCE(NULLIF($3, ''), operating_system),
			operating_system_version = COALESCE(NULLIF($4, ''), operating_system_version),
			architecture = COALESCE(NULLIF($5, ''), architecture)
		WHERE id = $1 AND deleted_at IS NULL`,
		serverID, agentVersion, h.OS, h.OSVersion, h.Architecture)
	return err
}

// Heartbeat atualiza presença e inventário do servidor.
func (r *Repository) Heartbeat(ctx context.Context, serverID string, hb Heartbeat) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := touchServer(ctx, tx, serverID, hb.AgentVersion, hb.Host); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Ingest grava a amostra de forma idempotente e atualiza discos e presença.
// stored=false indica amostra repetida (mesmo servidor e collected_at): nada é duplicado.
func (r *Repository) Ingest(ctx context.Context, serverID string, p Payload) (stored bool, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var rx, tx2 *int64
	if p.Network != nil {
		rx, tx2 = &p.Network.RXBytesTotal, &p.Network.TXBytesTotal
	}
	var l1, l5, l15 *float64
	if la := p.CPU.LoadAverage; la != nil {
		l1, l5, l15 = &la.M1, &la.M5, &la.M15
	}
	tag, err := tx.Exec(ctx, `INSERT INTO server_metrics (
			server_id, collected_at, cpu_usage_percent, cpu_count,
			load_average_1m, load_average_5m, load_average_15m,
			memory_total_bytes, memory_used_bytes, memory_available_bytes,
			swap_total_bytes, swap_used_bytes,
			network_rx_bytes_total, network_tx_bytes_total, uptime_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (server_id, collected_at) DO NOTHING`,
		serverID, p.CollectedAt, *p.CPU.UsagePercent, p.CPU.Count, l1, l5, l15,
		p.Memory.TotalBytes, p.Memory.UsedBytes, p.Memory.AvailableBytes,
		p.Memory.SwapTotalBytes, p.Memory.SwapUsedBytes, rx, tx2, p.Host.UptimeSeconds)
	if err != nil {
		return false, err
	}
	stored = tag.RowsAffected() == 1

	if stored && len(p.Disks) > 0 {
		if err := upsertDisks(ctx, tx, serverID, p); err != nil {
			return false, err
		}
	}
	if err := touchServer(ctx, tx, serverID, p.AgentVersion, p.Host); err != nil {
		return false, err
	}
	return stored, tx.Commit(ctx)
}

// upsertDisks mantém uma linha por (servidor, ponto de montagem). Amostras mais
// antigas que a já gravada não sobrescrevem (chegada fora de ordem), e volumes
// ausentes na coleta mais recente são removidos.
func upsertDisks(ctx context.Context, tx pgx.Tx, serverID string, p Payload) error {
	mounts := make([]string, 0, len(p.Disks))
	for _, d := range p.Disks {
		mounts = append(mounts, d.MountPoint)
		if _, err := tx.Exec(ctx, `INSERT INTO server_disks
				(server_id, mount_point, filesystem, total_bytes, used_bytes, available_bytes, collected_at)
			VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7)
			ON CONFLICT (server_id, mount_point) DO UPDATE SET
				filesystem = EXCLUDED.filesystem, total_bytes = EXCLUDED.total_bytes,
				used_bytes = EXCLUDED.used_bytes, available_bytes = EXCLUDED.available_bytes,
				collected_at = EXCLUDED.collected_at
			WHERE server_disks.collected_at <= EXCLUDED.collected_at`,
			serverID, d.MountPoint, d.Filesystem, d.TotalBytes, d.UsedBytes, d.AvailableBytes, p.CollectedAt); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `DELETE FROM server_disks
		WHERE server_id = $1 AND collected_at < $2 AND NOT (mount_point = ANY($3))`,
		serverID, p.CollectedAt, mounts)
	return err
}
