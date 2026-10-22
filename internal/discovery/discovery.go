// Package discovery implementa a descoberta automática de serviços do sistema (ssh, cron, nginx,
// redis, postgresql...). Ninguém precisa cadastrar nada: o agente procura cada serviço do
// catálogo no próprio host e envia só FATOS (status, origem, unidade). A API valida esses fatos
// contra um vocabulário fechado e é ela quem gera o texto "o que fazer", então um agente
// comprometido não consegue injetar instruções na tela do administrador.
package discovery

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/validation"
)

const (
	StatusAvailable = "available" // em execução
	StatusStopped   = "stopped"   // instalado, mas parado/desativado
	StatusNotFound  = "not_found" // não instalado (nem em container, no caso de redis/postgresql)
)

const (
	SourceSystemd = "systemd" // unidade do systemd no host
	SourceProcess = "process" // processo no host, fora de uma unidade conhecida
	SourceDocker  = "docker"  // processo/porta publicada por um container Docker
)

// Spec descreve como encontrar um serviço. É só dado: o agente é quem sabe verificar.
type Spec struct {
	Key   string
	Name  string
	Units []string // unidades systemd; "prefixo@*" casa instâncias (ex.: postgresql@16-main)
	Procs []string // nome do processo em /proc/<pid>/comm (até 15 caracteres)
	Ports []int    // portas TCP em escuta que indicam o serviço no host
	// DockerPort > 0 habilita a busca em containers: processo do serviço em cgroup do Docker ou
	// docker-proxy publicando essa porta do container.
	DockerPort int
}

// Catalog é a lista, em ordem de exibição, dos serviços procurados.
var Catalog = []Spec{
	{Key: "ssh", Name: "SSH", Units: []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"}, Procs: []string{"sshd"}, Ports: []int{22}},
	{Key: "journald", Name: "systemd-journald", Units: []string{"systemd-journald.service"}, Procs: []string{"systemd-journal"}},
	{Key: "cron", Name: "Cron", Units: []string{"cron.service", "crond.service"}, Procs: []string{"cron", "crond"}},
	{Key: "timesyncd", Name: "systemd-timesyncd", Units: []string{"systemd-timesyncd.service"}, Procs: []string{"systemd-timesyn"}},
	{Key: "ufw", Name: "UFW (firewall)", Units: []string{"ufw.service"}},
	{Key: "rsyslog", Name: "rsyslog", Units: []string{"rsyslog.service"}, Procs: []string{"rsyslogd"}},
	{Key: "nginx", Name: "Nginx", Units: []string{"nginx.service"}, Procs: []string{"nginx"}},
	{Key: "redis", Name: "Redis", Units: []string{"redis-server.service", "redis.service", "redis@*"}, Procs: []string{"redis-server"}, Ports: []int{6379}, DockerPort: 6379},
	{Key: "docker", Name: "Docker", Units: []string{"docker.service", "docker.socket"}, Procs: []string{"dockerd"}},
	{Key: "postgresql", Name: "PostgreSQL", Units: []string{"postgresql.service", "postgresql@*"}, Procs: []string{"postgres", "postmaster"}, Ports: []int{5432}, DockerPort: 5432},
}

// Lookup devolve o item do catálogo pela chave.
func Lookup(key string) (Spec, bool) {
	for _, s := range Catalog {
		if s.Key == key {
			return s, true
		}
	}
	return Spec{}, false
}

// Finding é o que o agente descobriu sobre um serviço.
type Finding struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Source string `json:"source,omitempty"`
	Unit   string `json:"unit,omitempty"`
}

// Report é o corpo de POST /agent/discovery: um retrato completo (substitui o anterior).
type Report struct {
	CheckedAt time.Time `json:"checked_at"`
	Services  []Finding `json:"services"`
}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,128}$`)

// Validate normaliza o relatório e recusa valores fora do vocabulário.
func (rep *Report) Validate(now time.Time) validation.Problems {
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
	if len(rep.Services) == 0 || len(rep.Services) > len(Catalog) {
		p.Add("services", "informe entre 1 e "+strconv.Itoa(len(Catalog))+" serviços")
		return p
	}
	seen := map[string]bool{}
	for i := range rep.Services {
		f := &rep.Services[i]
		field := func(n string) string { return "services[" + strconv.Itoa(i) + "]." + n }
		if _, ok := Lookup(f.Key); !ok {
			p.Add(field("key"), "serviço desconhecido")
		} else if seen[f.Key] {
			p.Add(field("key"), "duplicado no relatório")
		}
		seen[f.Key] = true
		switch f.Status {
		case StatusAvailable, StatusStopped, StatusNotFound:
		default:
			p.Add(field("status"), "deve ser available, stopped ou not_found")
		}
		switch f.Source {
		case SourceSystemd, SourceProcess, SourceDocker:
			if f.Status == StatusNotFound {
				p.Add(field("source"), "não se aplica a serviço não encontrado")
			}
		case "":
			if f.Status == StatusAvailable {
				p.Add(field("source"), "é obrigatório para serviço disponível")
			}
		default:
			p.Add(field("source"), "deve ser systemd, process ou docker")
		}
		if f.Unit != "" && !unitRe.MatchString(f.Unit) {
			p.Add(field("unit"), "nome de unidade inválido")
		}
	}
	return p
}

// Item é a visão devolvida ao frontend: o fato + nome amigável + o que fazer.
type Item struct {
	Key             string     `json:"key"`
	Name            string     `json:"name"`
	Available       bool       `json:"available"`
	Status          string     `json:"status"`
	Source          string     `json:"source"`
	Unit            string     `json:"unit"`
	Action          string     `json:"action"` // vazio quando já está disponível
	CheckedAt       time.Time  `json:"checked_at"`
	StatusChangedAt *time.Time `json:"status_changed_at"`
}

// NewItem monta o item de exibição a partir de um fato guardado.
func NewItem(key, status, source, unit string, checkedAt time.Time, changedAt *time.Time) Item {
	name := key
	if s, ok := Lookup(key); ok {
		name = s.Name
	}
	it := Item{Key: key, Name: name, Available: status == StatusAvailable, Status: status, Source: source, Unit: unit,
		CheckedAt: checkedAt, StatusChangedAt: changedAt}
	if !it.Available {
		it.Action = Action(key, status, unit)
	}
	return it
}

// Summary conta serviços disponíveis e indisponíveis.
type Summary struct {
	Total       int `json:"total"`
	Available   int `json:"available"`
	Unavailable int `json:"unavailable"`
}

func Summarize(items []Item) Summary {
	s := Summary{Total: len(items)}
	for _, it := range items {
		if it.Available {
			s.Available++
		} else {
			s.Unavailable++
		}
	}
	return s
}

// Action diz o que fazer para o serviço ficar disponível (comandos para Debian/Ubuntu).
func Action(key, status, unit string) string {
	if status == StatusStopped {
		if key == "ufw" {
			return "O UFW está instalado, mas desativado. Antes de ativar, libere o acesso SSH para não perder a conexão: " +
				"sudo ufw allow OpenSSH && sudo ufw enable"
		}
		if unit == "" {
			if s, ok := Lookup(key); ok && len(s.Units) > 0 {
				unit = s.Units[0]
			}
		}
		unit = strings.TrimSuffix(unit, "*")
		return "Instalado, mas parado. Inicie e habilite na inicialização: sudo systemctl enable --now " + unit
	}
	switch key {
	case "ssh":
		return "Instale e inicie: sudo apt install openssh-server && sudo systemctl enable --now ssh"
	case "journald":
		return "O journald faz parte do systemd e deveria existir. Verifique: systemctl status systemd-journald"
	case "cron":
		return "Instale e inicie: sudo apt install cron && sudo systemctl enable --now cron"
	case "timesyncd":
		return "Instale e inicie: sudo apt install systemd-timesyncd && sudo systemctl enable --now systemd-timesyncd " +
			"(se o servidor já sincroniza o relógio com chrony ou ntp, não é necessário)"
	case "ufw":
		return "Instale e ative (libere o SSH antes): sudo apt install ufw && sudo ufw allow OpenSSH && sudo ufw enable"
	case "rsyslog":
		return "Instale e inicie: sudo apt install rsyslog && sudo systemctl enable --now rsyslog"
	case "nginx":
		return "Instale e inicie: sudo apt install nginx && sudo systemctl enable --now nginx"
	case "docker":
		return "Instale e inicie: sudo apt install docker.io && sudo systemctl enable --now docker"
	case "redis":
		return "Não encontrado no host nem em container Docker. Instale no host: sudo apt install redis-server && " +
			"sudo systemctl enable --now redis-server — ou suba um container: " +
			"docker run -d --name redis --restart unless-stopped -p 127.0.0.1:6379:6379 redis:7"
	case "postgresql":
		return "Não encontrado no host nem em container Docker. Instale no host: sudo apt install postgresql && " +
			"sudo systemctl enable --now postgresql — ou suba um container: " +
			"docker run -d --name postgres --restart unless-stopped -e POSTGRES_PASSWORD=<defina-uma-senha> " +
			"-p 127.0.0.1:5432:5432 postgres:16"
	}
	return "Serviço não encontrado neste servidor."
}
