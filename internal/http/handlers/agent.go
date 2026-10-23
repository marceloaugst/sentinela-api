package handlers

import (
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"net/http"
	"time"

	"sentinela/internal/agents"
	"sentinela/internal/discovery"
	"sentinela/internal/dockerhost"
	"sentinela/internal/events"
	"sentinela/internal/http/response"
	"sentinela/internal/metrics"
	"sentinela/internal/procs"
	"sentinela/internal/services"
	"sentinela/internal/svcactions"
)

// MaxAgentBodyBytes limita o corpo das requisições de agentes.
const MaxAgentBodyBytes = 64 << 10

type Agent struct {
	Metrics          *metrics.Repository
	Services         *services.Repository
	Discovery        *discovery.Repository
	Docker           *dockerhost.Repository
	Procs            *procs.Repository
	ProcHistory      ProcHistoryStore // nil = sem ClickHouse
	SvcCommands      *svcactions.Repository
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
	if _, ok := identity(w, r); !ok {
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"collect_interval_seconds":  int(h.CollectInterval.Seconds()),
		"heartbeat_timeout_seconds": int(h.HeartbeatTimeout.Seconds()),
		"max_payload_bytes":         MaxAgentBodyBytes,
		"max_disks":                 metrics.MaxDisks,
	}, nil)
}

// POST /agent/discovery: retrato dos serviços do sistema encontrados pelo agente. O servidor vem
// da credencial; o agente só informa fatos de um vocabulário fechado.
func (h Agent) PostDiscovery(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var rep discovery.Report
	if !response.Decode(w, r, &rep) {
		return
	}
	if p := rep.Validate(h.now()); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if err := h.Discovery.Replace(r.Context(), id.ServerID, rep); err != nil {
		h.Log.Error("falha ao gravar descoberta de serviços", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	// Liga a descoberta aos alertas: falha aqui não desfaz o retrato já gravado (o próximo relatório repete).
	if err := h.Services.SyncDiscovered(r.Context(), id.ServerID, discoveredStates(rep), rep.CheckedAt); err != nil {
		h.Log.Error("falha ao sincronizar serviços descobertos", "err", err, "server_id", id.ServerID)
	}
	response.JSON(w, http.StatusOK, map[string]any{"stored": len(rep.Services)}, nil)
}

func discoveredStates(rep discovery.Report) []services.Discovered {
	out := make([]services.Discovered, 0, len(rep.Services))
	for _, f := range rep.Services {
		spec, ok := discovery.Lookup(f.Key)
		if !ok {
			continue
		}
		d := services.Discovered{Key: f.Key, Name: spec.Name, Target: f.Unit, Up: f.Status == discovery.StatusAvailable}
		if d.Target == "" {
			d.Target = f.Key
		}
		switch f.Status {
		case discovery.StatusStopped:
			d.Reason = "instalado, mas parado ou desativado"
		case discovery.StatusNotFound:
			d.Reason = "não encontrado (parou ou foi removido)"
		}
		out = append(out, d)
	}
	return out
}
