package alerts

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

var (
	ErrRuleNotFound  = errors.New("regra não encontrada")
	ErrAlertNotFound = errors.New("alerta não encontrado")
	ErrInvalidState  = errors.New("estado do alerta não permite a operação")
)

const (
	MetricCPU         = "cpu_usage_percent"
	MetricMemory      = "memory_used_percent"
	MetricDisk        = "disk_used_percent"
	MetricLoad        = "load_average_1m"
	MetricOffline     = "server_offline" // valor = segundos sem comunicação
	MetricServiceDown = "service_down"   // valor = 1 se o serviço está down, senão 0
	MetricSwap        = "swap_used_percent"
	MetricLoadPerCPU  = "load_per_cpu" // load average (1 min) dividido pelo número de CPUs

	// Métricas de sistema vindas do ClickHouse (coletadas pelo agente; ver internal/sysmetrics).
	MetricOOM         = "oom_kills_10m"      // processos mortos pelo OOM Killer nos últimos 10 min
	MetricInodes      = "inode_used_percent" // pior ponto de montagem
	MetricDiskLatency = "disk_latency_ms"    // pior dispositivo
	MetricNTP         = "ntp_unsynchronized" // 1 = relógio sem sincronizar
	MetricUpdates     = "security_updates"   // atualizações de segurança pendentes
	MetricCert        = "cert_days_left"     // dias até o primeiro certificado vencer
)

type Rule struct {
	ID              string    `json:"id"`
	Code            *string   `json:"code"` // identificador estável da regra do catálogo
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	MetricName      string    `json:"metric_name"`
	Operator        string    `json:"operator"`
	Threshold       float64   `json:"threshold"`
	Priority        int       `json:"priority"` // 1 (P1, crítico) a 4 (P4, informativo)
	Severity        string    `json:"severity"`
	DurationSeconds int       `json:"duration_seconds"`
	RecoverySeconds int       `json:"recovery_seconds"`
	ServerID        *string   `json:"server_id"` // sempre nulo: as regras do catálogo valem para todos os servidores
	IsEnabled       bool      `json:"is_enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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
	case MetricLoadPerCPU:
		return fmt.Sprintf("Load average de %.2f por CPU (%s)", value, limit)
	case MetricSwap:
		return fmt.Sprintf("Uso de swap em %.1f%% (%s%%)", value, limit)
	case MetricOOM:
		return fmt.Sprintf("O OOM Killer encerrou %.0f processo(s) nos últimos 10 min: falta de memória", value)
	case MetricInodes:
		return fmt.Sprintf("Inodes em %.1f%% em %s (%s%%)", value, detail, limit)
	case MetricDiskLatency:
		return fmt.Sprintf("Latência de disco em %.0f ms em %s (%s ms)", value, detail, limit)
	case MetricNTP:
		return "Relógio do sistema sem sincronização NTP"
	case MetricUpdates:
		return fmt.Sprintf("%.0f atualização(ões) de segurança pendente(s)", value)
	case MetricCert:
		if value < 0 {
			return fmt.Sprintf("Certificado de %s VENCIDO há %.0f dia(s)", detail, -value)
		}
		return fmt.Sprintf("Certificado de %s vence em %.0f dia(s)", detail, value)
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
