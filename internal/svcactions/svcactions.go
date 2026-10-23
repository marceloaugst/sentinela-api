// Package svcactions implementa os comandos de serviço (iniciar, parar, reiniciar). O usuário pede pela
// API (papel operator), a API registra o pedido e a auditoria, e o agente — que só faz requisições de saída —
// busca o comando, executa `systemctl` sobre uma unidade da própria lista fixa e devolve o resultado.
// A API nunca manda ao agente um nome de unidade nem um comando: só (chave do catálogo, ação).
package svcactions

import (
	"time"

	"sentinela/internal/discovery"
	"sentinela/internal/validation"
)

const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
)

const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusExpired   = "expired"
)

// Prazos: um pedido que o agente não pegou a tempo expira (não pode ser executado horas depois) e um
// comando "em execução" sem resultado vira falha.
const (
	PendingTTL = 2 * time.Minute
	RunningTTL = 5 * time.Minute
)

// Controllable é o que o frontend pode oferecer por serviço. journald e ufw ficam de fora: derrubar o
// journald perde logs e o ufw não é um daemon (liga/desliga regras de firewall — risco de perder o SSH).
var controllable = map[string][]string{
	"ssh":        {ActionStart, ActionRestart}, // parar o SSH pode trancar o administrador fora do servidor
	"cron":       {ActionStart, ActionStop, ActionRestart},
	"timesyncd":  {ActionStart, ActionStop, ActionRestart},
	"rsyslog":    {ActionStart, ActionStop, ActionRestart},
	"nginx":      {ActionStart, ActionStop, ActionRestart},
	"redis":      {ActionStart, ActionStop, ActionRestart},
	"docker":     {ActionStart, ActionStop, ActionRestart},
	"postgresql": {ActionStart, ActionStop, ActionRestart},
}

// ValidAction informa se a ação existe.
func ValidAction(a string) bool { return a == ActionStart || a == ActionStop || a == ActionRestart }

// Allowed devolve as ações permitidas para um serviço do catálogo, dado o estado descoberto. Só unidades
// systemd são controláveis (processos soltos e containers Docker não: exigiriam o socket do Docker = root).
//   - disponível via systemd: parar e reiniciar (e iniciar não faz sentido);
//   - instalado e parado: iniciar.
func Allowed(key, status, source, unit string) []string {
	base, ok := controllable[key]
	if !ok || unit == "" {
		return nil
	}
	var out []string
	for _, a := range base {
		switch {
		case status == discovery.StatusAvailable && source == discovery.SourceSystemd && a != ActionStart:
			out = append(out, a)
		case status == discovery.StatusStopped && a == ActionStart:
			out = append(out, a)
		}
	}
	return out
}

// Contains informa se a lista tem a ação.
func Contains(list []string, a string) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// Command é o pedido como a API o devolve ao frontend.
type Command struct {
	ID          string     `json:"id"`
	ServerID    string     `json:"server_id"`
	ServiceKey  string     `json:"service_key"`
	ServiceName string     `json:"service_name"`
	Unit        string     `json:"unit"`   // unidade systemd; para container, o nome do container
	Target      string     `json:"target"` // id do container (vazio = comando de serviço systemd)
	Action      string     `json:"action"`
	Status      string     `json:"status"`
	RequestedBy *string    `json:"requested_by"`
	Actor       string     `json:"requested_actor"`
	Message     string     `json:"message"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

// Pending é o que o agente recebe: a chave do catálogo e a ação (para container, também o id dele).
// Nunca há nome de unidade nem comando livre.
type Pending struct {
	ID         string `json:"id"`
	ServiceKey string `json:"service_key"`
	Action     string `json:"action"`
	Target     string `json:"target,omitempty"`
}

// Result é o corpo de POST /agent/commands/{id}/result.
type Result struct {
	Status  string `json:"status"` // succeeded | failed
	Message string `json:"message"`
}

// Validate normaliza o resultado enviado pelo agente.
func (r *Result) Validate() validation.Problems {
	var p validation.Problems
	switch r.Status {
	case StatusSucceeded, StatusFailed:
	default:
		p.Add("status", "deve ser succeeded ou failed")
	}
	r.Message = sanitize(r.Message)
	return p
}

// sanitize remove controles e limita o texto vindo do agente (nunca é interpretado, só exibido).
func sanitize(s string) string {
	b := make([]rune, 0, len(s))
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			c = ' '
		}
		b = append(b, c)
		if len(b) >= 300 {
			break
		}
	}
	return string(b)
}
