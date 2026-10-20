// Package services implementa serviços monitorados: cadastro, verificações HTTP executadas pela
// API (com proteção contra SSRF) e verificações locais (tcp/systemd) executadas pelo agente.
package services

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/ssrf"
	"sentinela/internal/validation"
)

var (
	ErrNotFound       = errors.New("serviço não encontrado")
	ErrServerNotFound = errors.New("servidor não encontrado")
	ErrConflict       = errors.New("já existe um serviço com esse nome neste servidor")
	ErrNotCentral     = errors.New("somente serviços http são verificados pela API")
)

const (
	TypeHTTP    = "http"    // verificado pela API
	TypeTCP     = "tcp"     // verificado pelo agente, apenas em loopback
	TypeSystemd = "systemd" // verificado pelo agente (sem executar comandos)
)

const (
	StatusUnknown  = "unknown"
	StatusUp       = "up"
	StatusDown     = "down"
	StatusDegraded = "degraded"
)

// Config guarda critérios e tempos da verificação (coluna jsonb).
type Config struct {
	TimeoutSeconds  int `json:"timeout_seconds"`
	IntervalSeconds int `json:"interval_seconds"`
	// Somente http:
	Method         string `json:"method,omitempty"`          // GET (padrão) ou HEAD
	ExpectedStatus []int  `json:"expected_status,omitempty"` // padrão [200]
	BodyContains   string `json:"body_contains,omitempty"`   // exige o trecho no corpo (até 64 KiB lidos)
	MaxLatencyMS   int    `json:"max_latency_ms,omitempty"`  // acima disso => degraded
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

type CreateInput struct {
	ServerID string  `json:"server_id"`
	Name     string  `json:"name"`
	Type     string  `json:"service_type"`
	Target   string  `json:"target"`
	Config   *Config `json:"config"`
}

type UpdateInput struct {
	Name   *string `json:"name"`
	Target *string `json:"target"`
	Config *Config `json:"config"`
}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,128}$`)

// Validador agrupa a política de rede usada para validar alvos http.
type Validator struct{ Policy ssrf.Policy }

func isLoopbackHost(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]"))
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// NormalizeUnit acrescenta ".service" quando o nome não tem sufixo de tipo de unidade.
func NormalizeUnit(u string) string {
	for _, suf := range []string{".service", ".socket", ".timer", ".mount", ".target", ".path"} {
		if strings.HasSuffix(u, suf) {
			return u
		}
	}
	return u + ".service"
}

func (v Validator) target(p *validation.Problems, typ, target string) string {
	target = strings.TrimSpace(target)
	switch typ {
	case TypeHTTP:
		if _, err := v.Policy.ValidateURL(target); err != nil {
			p.Add("target", err.Error())
		}
	case TypeTCP:
		host, port, err := splitHostPort(target)
		switch {
		case err != nil:
			p.Add("target", "use o formato host:porta (ex.: 127.0.0.1:5432)")
		case !isLoopbackHost(host):
			p.Add("target", "verificações tcp só são permitidas em loopback (localhost, 127.0.0.1 ou ::1), pois são executadas pelo agente")
		case port < 1 || port > 65535:
			p.Add("target", "porta inválida")
		}
	case TypeSystemd:
		if !unitRe.MatchString(target) {
			p.Add("target", "nome de unidade inválido (letras, números e : _ . @ -)")
		}
	}
	return target
}

func splitHostPort(s string) (string, int, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", 0, errors.New("formato")
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, err
	}
	return s[:i], port, nil
}

// applyConfig valida e aplica padrões, devolvendo a configuração efetiva.
func applyConfig(p *validation.Problems, typ string, in *Config) Config {
	var c Config
	if in != nil {
		c = *in
	}
	defTimeout, maxTimeout := 10, 30
	if typ != TypeHTTP {
		defTimeout, maxTimeout = 3, 10
	}
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 60
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = defTimeout
		if c.IntervalSeconds >= 10 && c.TimeoutSeconds >= c.IntervalSeconds {
			c.TimeoutSeconds = c.IntervalSeconds / 2 // padrão sempre cabe dentro do intervalo escolhido
		}
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > maxTimeout {
		p.Add("config.timeout_seconds", "deve estar entre 1 e "+strconv.Itoa(maxTimeout))
	}
	if c.IntervalSeconds < 10 || c.IntervalSeconds > 3600 {
		p.Add("config.interval_seconds", "deve estar entre 10 e 3600")
	}
	if c.TimeoutSeconds >= c.IntervalSeconds && c.IntervalSeconds >= 10 {
		p.Add("config.timeout_seconds", "deve ser menor que o intervalo")
	}
	if typ != TypeHTTP {
		if c.Method != "" || len(c.ExpectedStatus) > 0 || c.BodyContains != "" || c.MaxLatencyMS != 0 {
			p.Add("config", "method, expected_status, body_contains e max_latency_ms só valem para serviços http")
		}
		return c
	}
	c.Method = strings.ToUpper(c.Method)
	switch c.Method {
	case "":
		c.Method = "GET"
	case "GET", "HEAD":
	default:
		p.Add("config.method", "deve ser GET ou HEAD")
	}
	if len(c.ExpectedStatus) == 0 {
		c.ExpectedStatus = []int{200}
	}
	if len(c.ExpectedStatus) > 20 {
		p.Add("config.expected_status", "no máximo 20 códigos")
	}
	for _, s := range c.ExpectedStatus {
		if s < 100 || s > 599 {
			p.Add("config.expected_status", "códigos devem estar entre 100 e 599")
			break
		}
	}
	if len(c.BodyContains) > 256 {
		p.Add("config.body_contains", "no máximo 256 caracteres")
	}
	if c.BodyContains != "" && c.Method == "HEAD" {
		p.Add("config.body_contains", "não é possível verificar o corpo com HEAD")
	}
	if c.MaxLatencyMS < 0 || c.MaxLatencyMS > 60000 {
		p.Add("config.max_latency_ms", "deve estar entre 0 e 60000")
	}
	return c
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Validate normaliza e valida; devolve a configuração efetiva a gravar.
func (v Validator) Create(in *CreateInput) (Config, validation.Problems) {
	var p validation.Problems
	if !uuidRe.MatchString(in.ServerID) {
		p.Add("server_id", "deve ser um UUID")
	}
	in.ServerID = strings.ToLower(in.ServerID)
	in.Name = p.Text("name", in.Name, 1, 120)
	switch in.Type {
	case TypeHTTP, TypeTCP, TypeSystemd:
		in.Target = v.target(&p, in.Type, in.Target)
	default:
		p.Add("service_type", "deve ser http, tcp ou systemd")
	}
	cfg := applyConfig(&p, in.Type, in.Config)
	return cfg, p
}

// Update valida o patch contra o serviço atual e devolve a configuração efetiva.
func (v Validator) Update(cur Service, in *UpdateInput) (Config, validation.Problems) {
	var p validation.Problems
	if in.Name == nil && in.Target == nil && in.Config == nil {
		p.Add("body", "informe ao menos um campo (name, target ou config)")
		return cur.Config, p
	}
	if in.Name != nil {
		n := p.Text("name", *in.Name, 1, 120)
		in.Name = &n
	}
	if in.Target != nil {
		t := v.target(&p, cur.Type, *in.Target)
		in.Target = &t
	}
	cfg := cur.Config
	if in.Config != nil {
		cfg = applyConfig(&p, cur.Type, in.Config)
	}
	return cfg, p
}

// Result é o resultado de uma verificação.
type Result struct {
	Status     string
	LatencyMS  *int
	StatusCode *int
	Error      string
}

// sanitizeError remove caracteres de controle e limita o tamanho (texto vindo de agentes).
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
