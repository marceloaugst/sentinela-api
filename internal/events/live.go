package events

import (
	"context"
	"log/slog"
	"time"
)

// MetricsUpdated é o payload de metrics.updated: o mínimo para atualizar cards e gráficos.
type MetricsUpdated struct {
	ServerID          string    `json:"server_id"`
	CollectedAt       time.Time `json:"collected_at"`
	CPUUsagePercent   float64   `json:"cpu_usage_percent"`
	MemoryUsedPercent *float64  `json:"memory_used_percent"`
}

// LivePublisher publica eventos efêmeros com limite de frequência por servidor.
type LivePublisher struct {
	Ex       Execer
	Log      *slog.Logger
	Throttle *Throttle
}

func NewLivePublisher(ex Execer, log *slog.Logger, minInterval time.Duration) *LivePublisher {
	return &LivePublisher{Ex: ex, Log: log, Throttle: NewThrottle(minInterval)}
}

// MetricsUpdated é melhor esforço: falhas só são registradas (a ingestão já foi confirmada).
func (p *LivePublisher) MetricsUpdated(ctx context.Context, ev MetricsUpdated) {
	if p == nil || !p.Throttle.Allow(ev.ServerID) {
		return
	}
	if err := PublishLive(ctx, p.Ex, TypeMetricsUpdated, ev.ServerID, ev); err != nil {
		p.Log.Warn("falha ao publicar metrics.updated", "err", err)
	}
}
