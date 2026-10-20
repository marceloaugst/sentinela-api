// Package retention remove métricas mais antigas que METRICS_RETENTION_DAYS.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/events"
	"sentinela/internal/telemetry"
)

// Lock consultivo: com várias instâncias da API, só uma executa a limpeza por vez.
const lockID int64 = 0x53454e52 // "SENR"

type Job struct {
	Pool *pgxpool.Pool
	Days int
	// EventsRetention: por quanto tempo o log de eventos do SSE (reconexão) é mantido; 0 = não limpar.
	EventsRetention time.Duration
	Interval        time.Duration
	Batch           int // linhas por DELETE (evita transações longas)
	Log             *slog.Logger
	Metrics         *telemetry.Metrics
	Now             func() time.Time
}

func (j *Job) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// Run executa imediatamente e depois a cada Interval, até o contexto terminar.
func (j *Job) Run(ctx context.Context) {
	t := time.NewTicker(j.Interval)
	defer t.Stop()
	for {
		if _, err := j.RunOnce(ctx); err != nil && ctx.Err() == nil {
			j.Log.Error("retenção falhou", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce apaga em lotes as métricas anteriores ao corte. Devolve o total removido
// (0 também quando outra instância já está executando).
func (j *Job) RunOnce(ctx context.Context) (total int64, err error) {
	start := time.Now()
	result := "ok"
	defer func() {
		if err != nil {
			result = "error"
		}
		if j.Metrics != nil {
			j.Metrics.JobDuration.WithLabelValues("retention", result).Observe(time.Since(start).Seconds())
			j.Metrics.RetentionDeleted.Add(float64(total))
		}
	}()

	conn, err := j.Pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&got); err != nil {
		return 0, err
	}
	if !got {
		result = "skipped"
		return 0, nil
	}
	defer func() {
		// o unlock não pode depender do contexto cancelado
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(uctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()

	cutoff := j.now().Add(-time.Duration(j.Days) * 24 * time.Hour)
	for ctx.Err() == nil {
		tag, err := conn.Exec(ctx, `DELETE FROM server_metrics WHERE (server_id, collected_at) IN (
			SELECT server_id, collected_at FROM server_metrics WHERE collected_at < $1 LIMIT $2)`, cutoff, j.Batch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(j.Batch) {
			break
		}
	}
	if j.EventsRetention > 0 {
		if n, err := events.Purge(ctx, j.Pool, j.now().Add(-j.EventsRetention)); err != nil {
			return total, err
		} else if n > 0 {
			j.Log.Info("eventos antigos removidos", "deleted", n)
		}
	}
	if total > 0 {
		j.Log.Info("retenção aplicada", "deleted", total, "cutoff", cutoff.UTC().Format(time.RFC3339))
	}
	return total, ctx.Err()
}
