// Package dockerhost descobre os containers Docker do servidor monitorado e os controla (iniciar, reiniciar).
// O agente fala com o daemon pelo socket Unix, só com as chamadas fixas deste pacote; a API nunca manda comandos
// livres: manda (id do container, ação) e o agente confere os dois contra a própria listagem antes de agir.
package dockerhost

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"sentinela/internal/validation"
)

// Status do Docker no servidor.
const (
	StatusOK           = "ok"
	StatusNotInstalled = "not_installed" // sem socket do Docker
	StatusNoAccess     = "no_access"     // Docker existe, mas o agente não tem permissão no socket
	StatusUnavailable  = "unavailable"   // socket existe, mas o daemon não responde (parado)
)

// Ações sobre um container.
const (
	ActionStart   = "start"
	ActionRestart = "restart"
)

const (
	MaxContainers = 100
	maxLogTail    = 2000
	maxText       = 300
)

var idRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidID informa se é um id completo de container (64 hex).
func ValidID(id string) bool { return idRe.MatchString(id) }

// ValidAction informa se a ação existe para containers.
func ValidAction(a string) bool { return a == ActionStart || a == ActionRestart }

// Container é um container como o agente o vê.
type Container struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Image      string     `json:"image"`
	State      string     `json:"state"`  // running, exited, created, paused, restarting, dead, removing
	Status     string     `json:"status"` // texto do Docker ("Up 3 hours", "Exited (1) 2 minutes ago")
	ExitCode   *int       `json:"exit_code"`
	OOMKilled  bool       `json:"oom_killed"`
	Error      string     `json:"error"`    // por que não está ativo (vazio quando está ativo)
	LogTail    string     `json:"log_tail"` // últimas linhas do log, só dos que não estão ativos
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	// Actions é preenchido pela API: o que o usuário pode pedir agora.
	Actions []string `json:"actions"`
}

// Report é o corpo de POST /agent/docker.
type Report struct {
	CheckedAt  time.Time   `json:"checked_at"`
	Status     string      `json:"status"`
	Message    string      `json:"message"`
	Containers []Container `json:"containers"`
}

// Active informa se o container está em execução (ou prestes a reiniciar sozinho).
func Active(state string) bool { return state == "running" || state == "restarting" }

// Allowed devolve as ações permitidas dado o estado: ativo reinicia, inativo inicia. Pausado e em remoção
// não têm ação (o Docker recusaria).
func Allowed(state string) []string {
	switch state {
	case "running", "restarting":
		return []string{ActionRestart}
	case "exited", "created", "dead":
		return []string{ActionStart}
	}
	return []string{}
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

// Validate confere e normaliza o relatório do agente. Textos livres são limpos e cortados (só são exibidos).
func (r *Report) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	if r.CheckedAt.IsZero() {
		p.Add("checked_at", "é obrigatório")
	} else if r.CheckedAt.After(now.Add(5*time.Minute)) || r.CheckedAt.Before(now.Add(-24*time.Hour)) {
		p.Add("checked_at", "fora da janela aceita")
	}
	switch r.Status {
	case StatusOK, StatusNotInstalled, StatusNoAccess, StatusUnavailable:
	default:
		p.Add("status", "deve ser ok, not_installed, no_access ou unavailable")
	}
	r.Message = clean(r.Message, maxText, false)
	if r.Status != StatusOK && len(r.Containers) > 0 {
		p.Add("containers", "só é aceito com status ok")
	}
	if len(r.Containers) > MaxContainers {
		p.Add("containers", "máximo de "+strconv.Itoa(MaxContainers))
		return p
	}
	if r.Containers == nil {
		r.Containers = []Container{}
	}
	seen := map[string]bool{}
	for i := range r.Containers {
		c := &r.Containers[i]
		field := func(n string) string { return "containers[" + strconv.Itoa(i) + "]." + n }
		if !ValidID(c.ID) {
			p.Add(field("id"), "deve ter 64 caracteres hexadecimais")
		} else if seen[c.ID] {
			p.Add(field("id"), "duplicado no relatório")
		}
		seen[c.ID] = true
		switch c.State {
		case "running", "exited", "created", "paused", "restarting", "dead", "removing":
		default:
			p.Add(field("state"), "estado desconhecido")
		}
		c.Name = clean(c.Name, 128, false)
		c.Image = clean(c.Image, 200, false)
		c.Status = clean(c.Status, 100, false)
		c.Error = clean(c.Error, maxText, false)
		c.LogTail = clean(c.LogTail, maxLogTail, true)
		c.Actions = nil
	}
	return p
}

// clean remove caracteres de controle (mantendo \n e \t se multiline) e corta no limite de caracteres.
func clean(s string, max int, multiline bool) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	b := make([]rune, 0, len(s))
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			if multiline && (c == '\n' || c == '\t') {
				b = append(b, c)
				continue
			}
			c = ' '
		}
		b = append(b, c)
		if len(b) >= max {
			break
		}
	}
	return strings.TrimSpace(string(b))
}
