package services

import (
	"context"
	"time"

	"sentinela/internal/validation"
)

// Contrato entre API e agente para verificações locais.

// AgentService é o que o agente recebe em /agent/config: apenas nomes e tempos,
// nunca comandos. O agente decide como verificar cada tipo, com código próprio.
type AgentService struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"service_type"`
	Target          string `json:"target"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	IntervalSeconds int    `json:"interval_seconds"`
}

type AgentResult struct {
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
	LatencyMS *int   `json:"latency_ms"`
	Error     string `json:"error"`
}

type AgentReport struct {
	CheckedAt time.Time     `json:"checked_at"`
	Results   []AgentResult `json:"results"`
}

const MaxReportResults = 100

func (rep *AgentReport) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	switch {
	case rep.CheckedAt.IsZero():
		p.Add("checked_at", "é obrigatório")
	case rep.CheckedAt.After(now.Add(2 * time.Minute)):
		p.Add("checked_at", "está no futuro além do tolerado")
	case rep.CheckedAt.Before(now.Add(-time.Hour)):
		p.Add("checked_at", "é antigo demais")
	}
	rep.CheckedAt = rep.CheckedAt.UTC()
	if len(rep.Results) == 0 || len(rep.Results) > MaxReportResults {
		p.Add("results", "informe entre 1 e 100 resultados")
		return p
	}
	seen := map[string]bool{}
	for i := range rep.Results {
		r := &rep.Results[i]
		f := func(n string) string { return "results[" + itoa(i) + "]." + n }
		if !uuidRe.MatchString(r.ServiceID) {
			p.Add(f("service_id"), "deve ser um UUID")
		}
		r.ServiceID = lower(r.ServiceID)
		if seen[r.ServiceID] {
			p.Add(f("service_id"), "duplicado no relatório")
		}
		seen[r.ServiceID] = true
		switch r.Status {
		case StatusUp, StatusDown, StatusDegraded:
		default:
			p.Add(f("status"), "deve ser up, down ou degraded")
		}
		if r.LatencyMS != nil && (*r.LatencyMS < 0 || *r.LatencyMS > 600000) {
			p.Add(f("latency_ms"), "deve estar entre 0 e 600000")
		}
		r.Error = SanitizeError(r.Error)
	}
	return p
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

type Rejected struct {
	ServiceID string `json:"service_id"`
	Reason    string `json:"reason"` // unknown_service | stale
}

// ForAgent lista os serviços verificados localmente pelo agente daquele servidor.
func (r *Repository) ForAgent(ctx context.Context, serverID string) ([]AgentService, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, name, service_type, target,
			COALESCE((config->>'timeout_seconds')::int, 3), COALESCE((config->>'interval_seconds')::int, 60)
		FROM monitored_services
		WHERE server_id = $1 AND deleted_at IS NULL AND service_type IN ('tcp','systemd') ORDER BY created_at, id`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentService{}
	for rows.Next() {
		var s AgentService
		if err := rows.Scan(&s.ID, &s.Name, &s.Type, &s.Target, &s.TimeoutSeconds, &s.IntervalSeconds); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RecordAgentReport grava os resultados enviados por um agente. O agente só altera serviços do
// próprio servidor e apenas dos tipos verificados localmente.
func (r *Repository) RecordAgentReport(ctx context.Context, serverID string, rep AgentReport) (accepted int, rejected []Rejected, err error) {
	local := []string{TypeTCP, TypeSystemd}
	for _, res := range rep.Results {
		ok, err := r.record(ctx, res.ServiceID, &serverID, local, Result{Status: res.Status, LatencyMS: res.LatencyMS, Error: res.Error}, rep.CheckedAt)
		if err != nil {
			return accepted, rejected, err
		}
		if ok {
			accepted++
			continue
		}
		var exists bool
		if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM monitored_services
			WHERE id = $1 AND server_id = $2 AND deleted_at IS NULL AND service_type IN ('tcp','systemd'))`,
			res.ServiceID, serverID).Scan(&exists); err != nil {
			return accepted, rejected, err
		}
		reason := "unknown_service"
		if exists {
			reason = "stale"
		}
		rejected = append(rejected, Rejected{ServiceID: res.ServiceID, Reason: reason})
	}
	return accepted, rejected, nil
}
