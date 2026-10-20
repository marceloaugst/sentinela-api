package telemetry

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

// Metrics são as métricas da própria API (não dos servidores monitorados).
type Metrics struct {
	Registry     *prometheus.Registry
	Requests     *prometheus.CounterVec
	Latency      *prometheus.HistogramVec
	InFlight     prometheus.Gauge
	InternalErrs prometheus.Counter
	// Volume de amostras de agentes recebidas, por resultado (stored|duplicate).
	Samples *prometheus.CounterVec
	// Tempo de processamento de tarefas em segundo plano, por tarefa e resultado.
	JobDuration      *prometheus.HistogramVec
	RetentionDeleted prometheus.Counter
	// Transições de alertas aplicadas pelo avaliador (fire, resolve, drop_pending...).
	AlertTransitions *prometheus.CounterVec
	// Notificações: resultado do envio (sent|retry|failed) e motivo das falhas.
	Notifications *prometheus.CounterVec
	ServiceChecks *prometheus.CounterVec
	// Stream SSE: conexões abertas e eventos entregues/descartados por cliente lento.
	SSEClients prometheus.Gauge
	SSEEvents  *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sentinela", Subsystem: "http", Name: "requests_total",
			Help: "Total de requisições HTTP.",
		}, []string{"method", "route", "status"}),
		Latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "sentinela", Subsystem: "http", Name: "request_duration_seconds",
			Help: "Latência das requisições HTTP.", Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		InFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "sentinela", Subsystem: "http", Name: "requests_in_flight",
			Help: "Requisições em andamento.",
		}),
		InternalErrs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "internal_errors_total",
			Help: "Erros internos (panics e respostas 5xx).",
		}),
		Samples: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "agent_samples_total",
			Help: "Amostras de métricas recebidas dos agentes.",
		}, []string{"result"}),
		JobDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "sentinela", Name: "job_duration_seconds",
			Help: "Duração das tarefas em segundo plano.", Buckets: prometheus.DefBuckets,
		}, []string{"job", "result"}),
		RetentionDeleted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "retention_deleted_rows_total",
			Help: "Linhas de métricas removidas pela política de retenção.",
		}),
		AlertTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "alert_transitions_total",
			Help: "Transições de estado de alertas aplicadas pelo avaliador.",
		}, []string{"action"}),
		Notifications: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "notifications_total",
			Help: "Resultado das tentativas de envio de notificações.",
		}, []string{"result"}),
		ServiceChecks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "service_checks_total",
			Help: "Verificações de serviços executadas pela API, por resultado.",
		}, []string{"status"}),
		SSEClients: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "sentinela", Name: "sse_clients",
			Help: "Conexões SSE abertas nesta instância.",
		}),
		SSEEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sentinela", Name: "sse_events_total",
			Help: "Eventos SSE por resultado (delivered|overflow).",
		}, []string{"result"}),
	}
	reg.MustRegister(m.Requests, m.Latency, m.InFlight, m.InternalErrs, m.Samples, m.JobDuration, m.RetentionDeleted, m.AlertTransitions, m.Notifications, m.ServiceChecks, m.SSEClients, m.SSEEvents,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// RegisterPool expõe estatísticas do pool pgx.
func (m *Metrics) RegisterPool(pool *pgxpool.Pool) {
	g := func(name, help string, f func(*pgxpool.Stat) float64) {
		m.Registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "sentinela", Subsystem: "db_pool", Name: name, Help: help,
		}, func() float64 { return f(pool.Stat()) }))
	}
	g("acquired_conns", "Conexões em uso.", func(s *pgxpool.Stat) float64 { return float64(s.AcquiredConns()) })
	g("idle_conns", "Conexões ociosas.", func(s *pgxpool.Stat) float64 { return float64(s.IdleConns()) })
	g("total_conns", "Total de conexões.", func(s *pgxpool.Stat) float64 { return float64(s.TotalConns()) })
	g("max_conns", "Máximo de conexões.", func(s *pgxpool.Stat) float64 { return float64(s.MaxConns()) })
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
