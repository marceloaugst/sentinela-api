// Package logs define o contrato de logs coletados pelos agentes (nginx, fail2ban, ufw) e a validação
// aplicada pela API antes de gravá-los.
//
// Logs são dados controlados por quem ataca (User-Agent, URL, nome de usuário do SSH...). Por isso toda
// entrada é saneada na borda: sem caracteres de controle, com tamanhos limitados e vocabulário fechado
// para source/type/severity.
package logs

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"sentinela/internal/validation"
)

const (
	SourceNginx    = "nginx"
	SourceFail2ban = "fail2ban"
	SourceFirewall = "firewall"
)

// Tipos de evento por fonte.
const (
	TypeAccess        = "access"
	TypeAccessSummary = "access_summary" // agregado por minuto do access log
	TypeError         = "error"
	TypeFound         = "found"
	TypeBan           = "ban"
	TypeUnban         = "unban"
	TypeAlreadyBanned = "already_banned"
	TypeBlock         = "block"
	TypeAllow         = "allow"
	TypeLimit         = "limit"
)

const (
	SevDebug    = "debug"
	SevInfo     = "info"
	SevWarning  = "warning"
	SevError    = "error"
	SevCritical = "critical"
)

// Limites.
const (
	MaxBatchEntries = 500
	MaxRawLen       = 2048
	MaxFieldValue   = 512
	maxFields       = 20
	maxFutureSkew   = 5 * time.Minute
	maxAge          = 30 * 24 * time.Hour
)

// Types é o vocabulário permitido por fonte.
var Types = map[string][]string{
	SourceNginx:    {TypeAccess, TypeAccessSummary, TypeError},
	SourceFail2ban: {TypeFound, TypeBan, TypeUnban, TypeAlreadyBanned},
	SourceFirewall: {TypeBlock, TypeAllow, TypeLimit},
}

var severities = map[string]bool{SevDebug: true, SevInfo: true, SevWarning: true, SevError: true, SevCritical: true}

// Entry é uma linha de log normalizada.
type Entry struct {
	Time     time.Time         `json:"time"`
	Source   string            `json:"source"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	IP       string            `json:"ip,omitempty"`     // IP de origem (cliente/atacante)
	Port     int               `json:"port,omitempty"`   // porta de destino (firewall)
	Status   int               `json:"status,omitempty"` // status HTTP (nginx)
	Fields   map[string]string `json:"fields,omitempty"`
	Raw      string            `json:"raw,omitempty"`
}

// Batch é o corpo de POST /agent/logs. BatchID torna o reenvio idempotente.
type Batch struct {
	BatchID string  `json:"batch_id"`
	Entries []Entry `json:"entries"`
}

var (
	batchIDRe  = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
	fieldKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Clean remove caracteres de controle (tabulação vira espaço), corrige UTF-8 inválido e limita a n runas.
func Clean(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(min(len(s), n*2))
	count := 0
	for _, r := range s {
		if count >= n {
			break
		}
		switch {
		case r == '\t':
			r = ' '
		case unicode.IsControl(r):
			continue
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// NormalizeIP devolve a forma canônica do IP (IPv4-mapeado vira IPv4) ou "", false.
func NormalizeIP(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return a.Unmap().WithZone("").String(), true
}

func typeAllowed(source, typ string) bool {
	for _, t := range Types[source] {
		if t == typ {
			return true
		}
	}
	return false
}

// Validate valida e SANEIA o lote no próprio lugar.
func (b *Batch) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	if !batchIDRe.MatchString(b.BatchID) {
		p.Add("batch_id", "deve ter de 8 a 64 caracteres [A-Za-z0-9-]")
	}
	if len(b.Entries) == 0 {
		p.Add("entries", "é obrigatório")
	}
	if len(b.Entries) > MaxBatchEntries {
		p.Add("entries", fmt.Sprintf("no máximo %d entradas por lote", MaxBatchEntries))
		return p
	}
	for i := range b.Entries {
		b.Entries[i].validate(fmt.Sprintf("entries[%d]", i), now, &p)
		if len(p) >= 20 { // não acumule centenas de mensagens
			break
		}
	}
	return p
}

func (e *Entry) validate(path string, now time.Time, p *validation.Problems) {
	if e.Time.IsZero() || e.Time.After(now.Add(maxFutureSkew)) || e.Time.Before(now.Add(-maxAge)) {
		p.Add(path+".time", "fora da janela aceita (até 30 dias no passado)")
	}
	e.Time = e.Time.UTC()
	if _, ok := Types[e.Source]; !ok {
		p.Add(path+".source", "valor inválido")
	} else if !typeAllowed(e.Source, e.Type) {
		p.Add(path+".type", "valor inválido para a fonte")
	}
	if !severities[e.Severity] {
		p.Add(path+".severity", "valor inválido")
	}
	if e.IP != "" {
		ip, ok := NormalizeIP(e.IP)
		if !ok {
			p.Add(path+".ip", "IP inválido")
		}
		e.IP = ip
	}
	if e.Port < 0 || e.Port > 65535 {
		p.Add(path+".port", "deve estar entre 0 e 65535")
	}
	if e.Status != 0 && (e.Status < 100 || e.Status > 599) {
		p.Add(path+".status", "deve estar entre 100 e 599")
	}
	if len(e.Fields) > maxFields {
		p.Add(path+".fields", "campos demais")
		e.Fields = nil
	}
	for k, v := range e.Fields {
		if !fieldKeyRe.MatchString(k) {
			p.Add(path+".fields", "nome de campo inválido")
			delete(e.Fields, k)
			continue
		}
		e.Fields[k] = Clean(v, MaxFieldValue)
	}
	e.Raw = Clean(e.Raw, MaxRawLen)
}
