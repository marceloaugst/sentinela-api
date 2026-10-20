package alerts

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/validation"
)

var (
	ErrRuleNotFound   = errors.New("regra não encontrada")
	ErrAlertNotFound  = errors.New("alerta não encontrado")
	ErrServerNotFound = errors.New("servidor não encontrado")
	ErrInvalidState   = errors.New("estado do alerta não permite a operação")
)

const (
	MetricCPU         = "cpu_usage_percent"
	MetricMemory      = "memory_used_percent"
	MetricDisk        = "disk_used_percent"
	MetricLoad        = "load_average_1m"
	MetricOffline     = "server_offline" // valor = segundos sem comunicação
	MetricServiceDown = "service_down"   // valor = 1 se o serviço está down, senão 0
)

var metrics = map[string]bool{MetricCPU: true, MetricMemory: true, MetricDisk: true, MetricLoad: true, MetricOffline: true, MetricServiceDown: true}
var operators = map[string]bool{">": true, ">=": true, "<": true, "<=": true, "==": true}
var severities = map[string]bool{"info": true, "warning": true, "critical": true}

type Rule struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	MetricName      string    `json:"metric_name"`
	Operator        string    `json:"operator"`
	Threshold       float64   `json:"threshold"`
	Severity        string    `json:"severity"`
	DurationSeconds int       `json:"duration_seconds"`
	RecoverySeconds int       `json:"recovery_seconds"`
	ServerID        *string   `json:"server_id"` // nulo = regra global
	IsEnabled       bool      `json:"is_enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CreateRuleInput struct {
	Name            string   `json:"name"`
	MetricName      string   `json:"metric_name"`
	Operator        string   `json:"operator"`
	Threshold       *float64 `json:"threshold"`
	Severity        string   `json:"severity"`
	DurationSeconds int      `json:"duration_seconds"`
	RecoverySeconds int      `json:"recovery_seconds"`
	ServerID        *string  `json:"server_id"`
	IsEnabled       *bool    `json:"is_enabled"`
}

type UpdateRuleInput struct {
	Name            *string  `json:"name"`
	MetricName      *string  `json:"metric_name"`
	Operator        *string  `json:"operator"`
	Threshold       *float64 `json:"threshold"`
	Severity        *string  `json:"severity"`
	DurationSeconds *int     `json:"duration_seconds"`
	RecoverySeconds *int     `json:"recovery_seconds"`
	ServerID        *string  `json:"server_id"` // não é possível voltar a global por PATCH; recrie a regra
	IsEnabled       *bool    `json:"is_enabled"`
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// validateRule confere a regra completa (usada na criação e, após o merge, no PATCH).
func validateRule(p *validation.Problems, r *Rule) {
	r.Name = p.Text("name", r.Name, 1, 120)
	if !metrics[r.MetricName] {
		p.Add("metric_name", "deve ser cpu_usage_percent, memory_used_percent, disk_used_percent, load_average_1m, server_offline ou service_down")
	}
	if !operators[r.Operator] {
		p.Add("operator", "deve ser >, >=, <, <= ou ==")
	}
	if !severities[r.Severity] {
		p.Add("severity", "deve ser info, warning ou critical")
	}
	if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) {
		p.Add("threshold", "valor inválido")
	}
	switch r.MetricName {
	case MetricCPU, MetricMemory, MetricDisk:
		if r.Threshold < 0 || r.Threshold > 100 {
			p.Add("threshold", "deve estar entre 0 e 100 (percentual)")
		}
	case MetricLoad:
		if r.Threshold < 0 || r.Threshold > 100000 {
			p.Add("threshold", "deve estar entre 0 e 100000")
		}
	case MetricOffline:
		if r.Operator != ">" && r.Operator != ">=" {
			p.Add("operator", "para server_offline use > ou >= (segundos sem comunicação)")
		}
		if r.Threshold < 1 || r.Threshold > 86400 {
			p.Add("threshold", "deve estar entre 1 e 86400 segundos")
		}
	case MetricServiceDown:
		if r.Operator != "==" || r.Threshold != 1 {
			p.Add("operator", "para service_down use operator \"==\" e threshold 1 (serviço indisponível)")
		}
	}
	if r.DurationSeconds < 0 || r.DurationSeconds > 86400 {
		p.Add("duration_seconds", "deve estar entre 0 e 86400")
	}
	if r.RecoverySeconds < 0 || r.RecoverySeconds > 86400 {
		p.Add("recovery_seconds", "deve estar entre 0 e 86400")
	}
	if r.ServerID != nil {
		if !uuidRe.MatchString(*r.ServerID) {
			p.Add("server_id", "deve ser um UUID")
		} else {
			s := strings.ToLower(*r.ServerID)
			r.ServerID = &s
		}
	}
}

func (in *CreateRuleInput) Validate() (Rule, validation.Problems) {
	var p validation.Problems
	r := Rule{Name: in.Name, MetricName: in.MetricName, Operator: in.Operator, Severity: in.Severity,
		DurationSeconds: in.DurationSeconds, RecoverySeconds: in.RecoverySeconds, ServerID: in.ServerID, IsEnabled: true}
	if in.Threshold == nil {
		p.Add("threshold", "é obrigatório")
	} else {
		r.Threshold = *in.Threshold
	}
	if in.IsEnabled != nil {
		r.IsEnabled = *in.IsEnabled
	}
	validateRule(&p, &r)
	return r, p
}

func (in *UpdateRuleInput) Validate(cur Rule) (Rule, validation.Problems) {
	var p validation.Problems
	if *in == (UpdateRuleInput{}) {
		p.Add("body", "informe ao menos um campo")
		return cur, p
	}
	r := cur
	if in.Name != nil {
		r.Name = *in.Name
	}
	if in.MetricName != nil {
		r.MetricName = *in.MetricName
	}
	if in.Operator != nil {
		r.Operator = *in.Operator
	}
	if in.Threshold != nil {
		r.Threshold = *in.Threshold
	}
	if in.Severity != nil {
		r.Severity = *in.Severity
	}
	if in.DurationSeconds != nil {
		r.DurationSeconds = *in.DurationSeconds
	}
	if in.RecoverySeconds != nil {
		r.RecoverySeconds = *in.RecoverySeconds
	}
	if in.ServerID != nil {
		r.ServerID = in.ServerID
	}
	if in.IsEnabled != nil {
		r.IsEnabled = *in.IsEnabled
	}
	validateRule(&p, &r)
	return r, p
}

// Compare aplica o operador da regra.
func Compare(op string, value, threshold float64) bool {
	switch op {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case "==":
		return value == threshold
	}
	return false
}

func num(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func humanDuration(secs float64) string {
	s := int(secs + 0.5)
	switch {
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case s < 3600:
		return fmt.Sprintf("%d min %d s", s/60, s%60)
	default:
		return fmt.Sprintf("%d h %d min", s/3600, (s%3600)/60)
	}
}

// Message monta o texto do alerta (português) a partir da regra e do valor observado.
func Message(r Rule, value float64, detail string) string {
	limit := fmt.Sprintf("limite: %s %s", r.Operator, num(r.Threshold))
	switch r.MetricName {
	case MetricCPU:
		return fmt.Sprintf("Uso de CPU em %.1f%% (%s%%)", value, limit)
	case MetricMemory:
		return fmt.Sprintf("Uso de memória em %.1f%% (%s%%)", value, limit)
	case MetricDisk:
		return fmt.Sprintf("Uso de disco em %.1f%% em %s (%s%%)", value, detail, limit)
	case MetricLoad:
		return fmt.Sprintf("Load average (1 min) em %.2f (%s)", value, limit)
	case MetricOffline:
		return fmt.Sprintf("Sem comunicação há %s (limite: %s %s)", humanDuration(value), r.Operator, humanDuration(r.Threshold))
	case MetricServiceDown:
		if detail != "" {
			return "Serviço indisponível: " + detail
		}
		return "Serviço indisponível"
	}
	return fmt.Sprintf("%s = %s (%s)", r.MetricName, num(value), limit)
}
