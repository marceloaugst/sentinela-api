// Package dashboard reúne consultas agregadas para o painel e o resumo por servidor.
package dashboard

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Limiares de distribuição de CPU (percentual de uso da última amostra de cada servidor).
const (
	CPUMediumFrom = 50.0
	CPUHighFrom   = 80.0
)

type Repository struct {
	pool             *pgxpool.Pool
	heartbeatTimeout time.Duration
}

func NewRepository(pool *pgxpool.Pool, heartbeatTimeout time.Duration) *Repository {
	return &Repository{pool: pool, heartbeatTimeout: heartbeatTimeout}
}

func (r *Repository) connExpr() string {
	return fmt.Sprintf(`CASE WHEN last_seen_at IS NULL THEN 'unknown'
		WHEN last_seen_at >= now() - interval '%d seconds' THEN 'online' ELSE 'offline' END`,
		int(r.heartbeatTimeout.Seconds()))
}

type ServerCounts struct {
	Total            int `json:"total"`
	Online           int `json:"online"`
	Offline          int `json:"offline"`
	Unknown          int `json:"unknown"`
	Maintenance      int `json:"maintenance"`
	Disabled         int `json:"disabled"`
	WithActiveAlerts int `json:"with_active_alerts"`
}

type AlertCounts struct {
	Active   int `json:"active"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

type TopServer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CPUDistribution struct {
	Low    int `json:"low"`    // < 50%
	Medium int `json:"medium"` // 50% a < 80%
	High   int `json:"high"`   // >= 80%
}

type CPUOverview struct {
	// Média ponderada pelo número de CPUs lógicas de cada servidor (CPUs sem contagem valem 1).
	WeightedAvgPercent *float64        `json:"weighted_avg_percent"`
	MaxPercent         *float64        `json:"max_percent"`
	TopServer          *TopServer      `json:"top_server"`
	Distribution       CPUDistribution `json:"distribution"`
}

// Capacity: Σ usado / Σ total entre servidores online. Nunca uma média simples de percentuais.
type Capacity struct {
	UsedBytes   int64    `json:"used_bytes"`
	TotalBytes  int64    `json:"total_bytes"`
	UsedPercent *float64 `json:"used_percent"`
}

type Resources struct {
	// Servidores online que contribuem para os agregados abaixo.
	ReportingServers int         `json:"reporting_servers"`
	CPU              CPUOverview `json:"cpu"`
	Memory           Capacity    `json:"memory"`
	Disk             Capacity    `json:"disk"`
}

type Overview struct {
	Servers   ServerCounts `json:"servers"`
	Alerts    AlertCounts  `json:"alerts"`
	Incidents struct {
		Open int `json:"open"`
	} `json:"incidents"`
	Resources Resources `json:"resources"`
	// DataAsOf é o recebimento mais recente entre as amostras usadas nos agregados.
	DataAsOf  *time.Time `json:"data_as_of"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Uma única consulta calcula todos os cards (CTEs compartilhadas), em vez de uma consulta por card.
func (r *Repository) overviewSQL() string {
	return `
WITH srv AS (
  SELECT id, name, status, ` + r.connExpr() + ` AS conn FROM servers WHERE deleted_at IS NULL
), lat AS (
  SELECT srv.id, srv.name, m.cpu_usage_percent AS cpu, greatest(coalesce(m.cpu_count, 1), 1) AS ncpu,
         m.memory_used_bytes AS mu, m.memory_total_bytes AS mt, m.received_at
  FROM srv
  JOIN LATERAL (SELECT * FROM server_metrics WHERE server_id = srv.id ORDER BY collected_at DESC LIMIT 1) m ON true
  WHERE srv.conn = 'online'
), act AS (
  -- alertas ativos apenas de servidores não removidos
  SELECT a.server_id, a.severity FROM alerts a JOIN srv ON srv.id = a.server_id WHERE a.status IN ('firing','acknowledged')
)
SELECT
  (SELECT count(*) FROM srv),
  (SELECT count(*) FROM srv WHERE conn = 'online'),
  (SELECT count(*) FROM srv WHERE conn = 'offline'),
  (SELECT count(*) FROM srv WHERE conn = 'unknown'),
  (SELECT count(*) FROM srv WHERE status = 'maintenance'),
  (SELECT count(*) FROM srv WHERE status = 'disabled'),
  (SELECT count(DISTINCT server_id) FROM act),
  (SELECT count(*) FROM act),
  (SELECT count(*) FROM act WHERE severity = 'critical'),
  (SELECT count(*) FROM act WHERE severity = 'warning'),
  (SELECT count(*) FROM act WHERE severity = 'info'),
  (SELECT count(*) FROM incidents i WHERE i.status = 'open' AND (i.server_id IS NULL OR i.server_id IN (SELECT id FROM srv))),
  (SELECT count(*) FROM lat),
  (SELECT sum(cpu * ncpu) / NULLIF(sum(ncpu), 0) FROM lat),
  (SELECT max(cpu) FROM lat),
  (SELECT id::text FROM lat ORDER BY cpu DESC, id LIMIT 1),
  (SELECT name FROM lat ORDER BY cpu DESC, id LIMIT 1),
  (SELECT count(*) FROM lat WHERE cpu < ` + fmt.Sprint(CPUMediumFrom) + `),
  (SELECT count(*) FROM lat WHERE cpu >= ` + fmt.Sprint(CPUMediumFrom) + ` AND cpu < ` + fmt.Sprint(CPUHighFrom) + `),
  (SELECT count(*) FROM lat WHERE cpu >= ` + fmt.Sprint(CPUHighFrom) + `),
  (SELECT coalesce(sum(mu), 0)::bigint FROM lat),
  (SELECT coalesce(sum(mt), 0)::bigint FROM lat),
  (SELECT coalesce(sum(d.used_bytes), 0)::bigint FROM server_disks d WHERE d.server_id IN (SELECT id FROM lat)),
  (SELECT coalesce(sum(d.total_bytes), 0)::bigint FROM server_disks d WHERE d.server_id IN (SELECT id FROM lat)),
  (SELECT max(received_at) FROM lat),
  now()`
}

func pct(used, total int64) *float64 {
	if total <= 0 {
		return nil
	}
	v := float64(used) / float64(total) * 100
	return &v
}

func (r *Repository) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	var topID, topName *string
	err := r.pool.QueryRow(ctx, r.overviewSQL()).Scan(
		&o.Servers.Total, &o.Servers.Online, &o.Servers.Offline, &o.Servers.Unknown,
		&o.Servers.Maintenance, &o.Servers.Disabled, &o.Servers.WithActiveAlerts,
		&o.Alerts.Active, &o.Alerts.Critical, &o.Alerts.Warning, &o.Alerts.Info,
		&o.Incidents.Open,
		&o.Resources.ReportingServers,
		&o.Resources.CPU.WeightedAvgPercent, &o.Resources.CPU.MaxPercent, &topID, &topName,
		&o.Resources.CPU.Distribution.Low, &o.Resources.CPU.Distribution.Medium, &o.Resources.CPU.Distribution.High,
		&o.Resources.Memory.UsedBytes, &o.Resources.Memory.TotalBytes,
		&o.Resources.Disk.UsedBytes, &o.Resources.Disk.TotalBytes,
		&o.DataAsOf, &o.UpdatedAt)
	if err != nil {
		return Overview{}, err
	}
	if topID != nil && topName != nil {
		o.Resources.CPU.TopServer = &TopServer{ID: *topID, Name: *topName}
	}
	o.Resources.Memory.UsedPercent = pct(o.Resources.Memory.UsedBytes, o.Resources.Memory.TotalBytes)
	o.Resources.Disk.UsedPercent = pct(o.Resources.Disk.UsedBytes, o.Resources.Disk.TotalBytes)
	return o, nil
}

// --- listas recentes ---

type RecentAlert struct {
	ID             string     `json:"id"`
	ServerID       string     `json:"server_id"`
	ServerName     string     `json:"server_name"`
	RuleID         string     `json:"rule_id"`
	RuleName       string     `json:"rule_name"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Message        string     `json:"message"`
	TriggeredAt    time.Time  `json:"triggered_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

// RecentAlerts: status "" = todos; "active" = não resolvidos; ou um estado específico.
func (r *Repository) RecentAlerts(ctx context.Context, status string, limit int) ([]RecentAlert, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.server_id, s.name, a.rule_id, ar.name, a.severity, a.status, a.message,
		       a.triggered_at, a.acknowledged_at, a.resolved_at
		FROM alerts a
		JOIN servers s ON s.id = a.server_id
		JOIN alert_rules ar ON ar.id = a.rule_id
		WHERE (($1 = '' AND a.status <> 'pending') OR ($1 = 'active' AND a.status IN ('firing','acknowledged')) OR a.status = $1)
		ORDER BY a.triggered_at DESC, a.id
		LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecentAlert{}
	for rows.Next() {
		var a RecentAlert
		if err := rows.Scan(&a.ID, &a.ServerID, &a.ServerName, &a.RuleID, &a.RuleName, &a.Severity, &a.Status,
			&a.Message, &a.TriggeredAt, &a.AcknowledgedAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type RecentIncident struct {
	ID              string     `json:"id"`
	ServerID        *string    `json:"server_id"`
	ServerName      *string    `json:"server_name"`
	Title           string     `json:"title"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	DurationSeconds int64      `json:"duration_seconds"` // incidente aberto: tempo decorrido até agora
}

func (r *Repository) RecentIncidents(ctx context.Context, status string, limit int) ([]RecentIncident, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT i.id, i.server_id, s.name, i.title, i.severity, i.status, i.started_at, i.resolved_at,
		       extract(epoch FROM coalesce(i.resolved_at, now()) - i.started_at)::bigint
		FROM incidents i LEFT JOIN servers s ON s.id = i.server_id
		WHERE ($1 = '' OR i.status = $1)
		ORDER BY i.started_at DESC, i.id
		LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecentIncident{}
	for rows.Next() {
		var i RecentIncident
		if err := rows.Scan(&i.ID, &i.ServerID, &i.ServerName, &i.Title, &i.Severity, &i.Status,
			&i.StartedAt, &i.ResolvedAt, &i.DurationSeconds); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
