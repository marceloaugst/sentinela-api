// Package procs lista os processos do servidor (CPU e memória) e encerra, a pedido da API, os poucos que o agente
// pode encerrar com segurança. O agente lê /proc e envia só FATOS (pid, nome, consumo, "restrição"); quem gera o texto
// que o administrador lê é a API, a partir de um vocabulário fechado, então um agente comprometido não injeta instruções.
//
// Encerrar é restrito: só processos do MESMO usuário do agente (ele não roda como root e não ganha privilégio por isso),
// fora do catálogo de serviços (esses têm Reiniciar/Parar), de containers, do sistema e do próprio agente. O pedido leva
// (pid, início do processo): o início evita atingir outro processo que reaproveitou o pid.
package procs

import (
	"math"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/discovery"
	"sentinela/internal/validation"
)

// Ações sobre um processo.
const (
	ActionTerminate = "terminate" // SIGTERM: pede para encerrar
	ActionKill      = "kill"      // SIGKILL: força
)

// ServiceKey é o service_key dos comandos de processo em service_commands.
const ServiceKey = "process"

// Restrições: por que um processo NÃO pode ser encerrado (vazio = pode).
const (
	RestrictNone      = ""
	RestrictCritical  = "critical"   // init, sshd, systemd, dockerd...
	RestrictSelf      = "self"       // o próprio agente
	RestrictContainer = "container"  // processo de container Docker
	RestrictService   = "service"    // serviço do catálogo (use Parar/Reiniciar)
	RestrictOtherUser = "other_user" // de outro usuário: o agente não tem permissão
)

const (
	MaxProcesses = 500 // aceitos pela API
	maxText      = 200
)

var restrictionText = map[string]string{
	RestrictCritical:  "Processo essencial do sistema: não pode ser encerrado por aqui.",
	RestrictSelf:      "É o próprio agente do Sentinela.",
	RestrictContainer: "Processo de um container Docker: use a tela do Docker (reiniciar o container).",
	RestrictService:   "Pertence a um serviço monitorado: use Parar ou Reiniciar na tela de serviços.",
	RestrictOtherUser: "Pertence a outro usuário e o agente não roda como root, então não tem permissão para encerrá-lo.",
}

// RestrictionText é o texto exibido para uma restrição (vazio se não houver).
func RestrictionText(r string) string { return restrictionText[r] }

// ValidAction informa se a ação existe.
func ValidAction(a string) bool { return a == ActionTerminate || a == ActionKill }

// Actions devolve as ações oferecidas para uma restrição.
func Actions(restriction string) []string {
	if restriction != RestrictNone {
		return []string{}
	}
	return []string{ActionTerminate, ActionKill}
}

// Process é um processo como o agente o vê.
type Process struct {
	PID         int     `json:"pid"`
	StartTime   uint64  `json:"start_time"` // início em ticks do boot (campo 22 de /proc/<pid>/stat): identifica o processo junto com o pid
	PPID        int     `json:"ppid"`
	Name        string  `json:"name"`
	Cmdline     string  `json:"cmdline"` // argumentos com segredos aparentes mascarados, cortado
	User        string  `json:"user"`
	State       string  `json:"state"`   // R, S, D, T, Z...
	Threads     int     `json:"threads"` // número de threads
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes int64   `json:"memory_bytes"` // RSS
	ServiceKey  string  `json:"service_key"`  // serviço do catálogo a que pertence (vazio = nenhum)
	Restriction string  `json:"restriction"`

	// Preenchidos pela API.
	MemoryPercent float64  `json:"memory_percent"`
	ServiceName   string   `json:"service_name"`
	Actions       []string `json:"actions"`
	Message       string   `json:"restriction_message"`
}

// Report é o corpo de POST /agent/processes e o que a API guarda.
type Report struct {
	CheckedAt        time.Time `json:"checked_at"`
	CPUs             int       `json:"cpus"`               // CPU% de um processo vai de 0 a 100*cpus
	MemoryTotalBytes int64     `json:"memory_total_bytes"` // RAM total do servidor
	Total            int       `json:"total"`              // processos de usuário existentes (a lista pode ser menor)
	Processes        []Process `json:"processes"`
}

// Target é o alvo de um comando: "<pid>:<start_time>".
func Target(pid int, start uint64) string {
	return strconv.Itoa(pid) + ":" + strconv.FormatUint(start, 10)
}

// ParseTarget lê o alvo de um comando.
func ParseTarget(s string) (pid int, start uint64, ok bool) {
	a, b, found := strings.Cut(s, ":")
	if !found {
		return 0, 0, false
	}
	p, err := strconv.Atoi(a)
	if err != nil || p <= 1 {
		return 0, 0, false
	}
	st, err := strconv.ParseUint(b, 10, 64)
	if err != nil || st == 0 {
		return 0, 0, false
	}
	return p, st, true
}

// Validate confere e normaliza o relatório do agente. Textos livres são limpos e cortados (só são exibidos).
func (r *Report) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	if r.CheckedAt.IsZero() {
		p.Add("checked_at", "é obrigatório")
	} else if r.CheckedAt.After(now.Add(5*time.Minute)) || r.CheckedAt.Before(now.Add(-24*time.Hour)) {
		p.Add("checked_at", "fora da janela aceita")
	}
	r.CheckedAt = r.CheckedAt.UTC()
	if r.CPUs < 1 || r.CPUs > 4096 {
		p.Add("cpus", "deve estar entre 1 e 4096")
	}
	if r.MemoryTotalBytes < 0 {
		p.Add("memory_total_bytes", "não pode ser negativo")
	}
	if r.Total < len(r.Processes) {
		r.Total = len(r.Processes)
	}
	if len(r.Processes) > MaxProcesses {
		p.Add("processes", "máximo de "+strconv.Itoa(MaxProcesses))
		return p
	}
	if r.Processes == nil {
		r.Processes = []Process{}
	}
	seen := map[int]bool{}
	for i := range r.Processes {
		pr := &r.Processes[i]
		field := func(n string) string { return "processes[" + strconv.Itoa(i) + "]." + n }
		if pr.PID < 1 || seen[pr.PID] {
			p.Add(field("pid"), "inválido ou duplicado")
		}
		seen[pr.PID] = true
		pr.Name = clean(pr.Name, 64)
		pr.Cmdline = clean(pr.Cmdline, maxText)
		pr.User = clean(pr.User, 48)
		if pr.Name == "" {
			p.Add(field("name"), "é obrigatório")
		}
		if len(pr.State) != 1 || !strings.Contains("RSDTtZXIPWK", pr.State) {
			p.Add(field("state"), "estado desconhecido")
		}
		if pr.Threads < 0 || pr.Threads > 10_000_000 || pr.PPID < 0 {
			p.Add(field("threads"), "valor inválido")
		}
		if math.IsNaN(pr.CPUPercent) || math.IsInf(pr.CPUPercent, 0) || pr.CPUPercent < 0 {
			p.Add(field("cpu_percent"), "valor inválido")
		} else if max := float64(r.CPUs) * 100; pr.CPUPercent > max {
			pr.CPUPercent = max
		}
		if pr.MemoryBytes < 0 {
			p.Add(field("memory_bytes"), "não pode ser negativo")
		}
		if pr.ServiceKey != "" {
			if _, ok := discovery.Lookup(pr.ServiceKey); !ok {
				p.Add(field("service_key"), "serviço desconhecido")
			}
		}
		switch pr.Restriction {
		case RestrictNone, RestrictCritical, RestrictSelf, RestrictContainer, RestrictService, RestrictOtherUser:
		default:
			p.Add(field("restriction"), "restrição desconhecida")
		}
		// campos da API: ignora o que o agente mandar
		pr.MemoryPercent, pr.ServiceName, pr.Actions, pr.Message = 0, "", nil, ""
	}
	return p
}

// Decorate preenche os campos calculados pela API.
func (r *Report) Decorate() {
	for i := range r.Processes {
		pr := &r.Processes[i]
		if r.MemoryTotalBytes > 0 {
			pr.MemoryPercent = math.Round(float64(pr.MemoryBytes)/float64(r.MemoryTotalBytes)*1000) / 10
		}
		if spec, ok := discovery.Lookup(pr.ServiceKey); ok {
			pr.ServiceName = spec.Name
		}
		pr.Actions = Actions(pr.Restriction)
		pr.Message = RestrictionText(pr.Restriction)
	}
}

// clean tira controles e limita o tamanho em runas.
func clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	b := make([]rune, 0, len(s))
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			c = ' '
		}
		b = append(b, c)
		if len(b) >= max {
			break
		}
	}
	return strings.TrimSpace(string(b))
}
