// Package services guarda o estado dos serviços monitorados. Não há cadastro: todos os serviços
// vêm da descoberta automática feita pelo agente (veja o pacote discovery e SyncDiscovered).
package services

import (
	"errors"
	"strings"
	"time"
)

var ErrNotFound = errors.New("serviço não encontrado")

// TypeDiscovered é o único tipo em uso: serviço achado sozinho pelo agente.
const TypeDiscovered = "discovered"

const (
	StatusUnknown  = "unknown"
	StatusUp       = "up"
	StatusDown     = "down"
	StatusDegraded = "degraded"
)

// Config é mantida só por compatibilidade do contrato da API (coluna jsonb).
type Config struct {
	TimeoutSeconds  int `json:"timeout_seconds"`
	IntervalSeconds int `json:"interval_seconds"`
}

type Service struct {
	ID                  string     `json:"id"`
	ServerID            string     `json:"server_id"`
	Name                string     `json:"name"`
	Type                string     `json:"service_type"`
	Target              string     `json:"target"`
	Config              Config     `json:"config"`
	Status              string     `json:"status"`
	LastCheckedAt       *time.Time `json:"last_checked_at"`
	LastError           *string    `json:"last_error"`
	LastLatencyMS       *int       `json:"last_latency_ms"`
	LastStatusCode      *int       `json:"last_status_code"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	StatusChangedAt     *time.Time `json:"status_changed_at"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Result é o resultado de uma verificação.
type Result struct {
	Status     string
	LatencyMS  *int
	StatusCode *int
	Error      string
}

// SanitizeError remove caracteres de controle e limita o tamanho do texto de erro.
func SanitizeError(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	return s
}
