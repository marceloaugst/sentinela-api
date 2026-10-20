package handlers

import (
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"net/http"
	"time"

	"sentinela/internal/agents"
	"sentinela/internal/events"
	"sentinela/internal/http/response"
	"sentinela/internal/metrics"
	"sentinela/internal/services"
)

// MaxAgentBodyBytes limita o corpo das requisições de agentes.
const MaxAgentBodyBytes = 64 << 10

type Agent struct {
	Metrics          *metrics.Repository
	Services         *services.Repository
	Log              *slog.Logger
	CollectInterval  time.Duration
	HeartbeatTimeout time.Duration
	// Samples conta amostras recebidas por resultado (opcional).
	Samples *prometheus.CounterVec
	// Live publica metrics.updated (efêmero, com limite de frequência); opcional.
	Live *events.LivePublisher
	// Now é injetável em testes.
	Now func() time.Time
}

func (h Agent) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// O servidor alvo vem SEMPRE da credencial; nenhum identificador de servidor é aceito no payload.
func identity(w http.ResponseWriter, r *http.Request) (agents.Identity, bool) {
	id, ok := agents.IdentityFrom(r.Context())
	if !ok {
		response.Internal(w)
	}
	return id, ok
}

func (h Agent) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var hb metrics.Heartbeat
	if !response.Decode(w, r, &hb) {
		return
	}
	if p := hb.Validate(); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if err := h.Metrics.Heartbeat(r.Context(), id.ServerID, hb); err != nil {
		h.Log.Error("falha no heartbeat", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"server_time": h.now().UTC()}, nil)
}

func (h Agent) PostMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var pl metrics.Payload
	if !response.Decode(w, r, &pl) {
		return
	}
	received := h.now()
	if p := pl.Validate(received); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	stored, err := h.Metrics.Ingest(r.Context(), id.ServerID, pl)
	if err != nil {
		h.Log.Error("falha ao gravar métricas", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	if stored {
		ev := events.MetricsUpdated{ServerID: id.ServerID, CollectedAt: pl.CollectedAt, CPUUsagePercent: *pl.CPU.UsagePercent}
		if pl.Memory.TotalBytes > 0 {
			v := float64(pl.Memory.UsedBytes) / float64(pl.Memory.TotalBytes) * 100
			ev.MemoryUsedPercent = &v
		}
		h.Live.MetricsUpdated(r.Context(), ev)
	}
	if h.Samples != nil {
		result := "stored"
		if !stored {
			result = "duplicate"
		}
		h.Samples.WithLabelValues(result).Inc()
	}
	// 200 nos dois casos: reenvio da mesma amostra é idempotente e o agente não deve retentar.
	response.JSON(w, http.StatusOK, map[string]any{"stored": stored, "duplicate": !stored, "received_at": received.UTC()}, nil)
}

// Config entrega apenas parâmetros operacionais não sensíveis. Nunca inclui segredos
// nem instruções/comandos para execução.
func (h Agent) Config(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	// Serviços a verificar localmente: apenas nomes e tempos; o agente decide como verificar.
	svcs, err := h.Services.ForAgent(r.Context(), id.ServerID)
	if err != nil {
		h.Log.Error("falha ao listar serviços do agente", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"services":                  svcs,
		"collect_interval_seconds":  int(h.CollectInterval.Seconds()),
		"heartbeat_timeout_seconds": int(h.HeartbeatTimeout.Seconds()),
		"max_payload_bytes":         MaxAgentBodyBytes,
		"max_disks":                 metrics.MaxDisks,
	}, nil)
}

// POST /agent/services: resultados das verificações locais (tcp/systemd). O agente só altera
// serviços do próprio servidor; ids desconhecidos ou resultados mais antigos são recusados.
func (h Agent) PostServices(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var rep services.AgentReport
	if !response.Decode(w, r, &rep) {
		return
	}
	if p := rep.Validate(h.now()); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	accepted, rejected, err := h.Services.RecordAgentReport(r.Context(), id.ServerID, rep)
	if err != nil {
		h.Log.Error("falha ao gravar serviços do agente", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	if rejected == nil {
		rejected = []services.Rejected{}
	}
	response.JSON(w, http.StatusOK, map[string]any{"accepted": accepted, "rejected": rejected}, nil)
}
