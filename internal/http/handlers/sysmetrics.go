package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"sentinela/internal/http/response"
	"sentinela/internal/sysmetrics"
)

// SystemStore é o que o handler precisa do ClickHouse.
type SystemStore interface {
	Ready() bool
	InsertSystem(ctx context.Context, serverID, batchID string, samples []sysmetrics.Sample) error
}

// SystemMetrics recebe as métricas de sistema do agente e as grava no ClickHouse.
type SystemMetrics struct {
	Store SystemStore // nil = recurso desativado (CLICKHOUSE_URL vazia)
	Log   *slog.Logger
	Now   func() time.Time
}

// MaxSystemBatchBytes limita o corpo de POST /agent/system-metrics.
const MaxSystemBatchBytes = 256 << 10

func (h *SystemMetrics) Post(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	if h.Store == nil || !h.Store.Ready() {
		response.Error(w, http.StatusServiceUnavailable, "LOGS_UNAVAILABLE", "O armazenamento de logs não está disponível.")
		return
	}
	var b sysmetrics.Batch
	if !response.Decode(w, r, &b) {
		return
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	if p := b.Validate(now); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if err := h.Store.InsertSystem(r.Context(), id.ServerID, b.BatchID, b.Samples); err != nil {
		h.Log.Error("falha ao gravar métricas de sistema", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"stored": len(b.Samples)}, nil)
}
