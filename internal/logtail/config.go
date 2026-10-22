package logtail

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Settings descreve quais logs o agente acompanha. Vazio (SENTINELA_LOGS não definida) = desativado.
type Settings struct {
	Sources   []string // nginx | fail2ban | ufw
	Paths     map[string]string
	NginxAll  bool // grava todo pedido do access log (padrão: só 4xx/5xx/suspeitos + resumo por minuto)
	FromStart bool
	StateFile string
}

var defaultPaths = map[string]string{
	"nginx_access": "/var/log/nginx/access.log",
	"nginx_error":  "/var/log/nginx/error.log",
	"fail2ban":     "/var/log/fail2ban.log",
	"ufw":          "/var/log/ufw.log",
}

// LoadSettings lê as variáveis SENTINELA_LOGS, SENTINELA_LOG_*_PATH e o diretório de estado.
func LoadSettings(getenv func(string) string) (Settings, error) {
	s := Settings{Paths: map[string]string{}}
	for k, v := range defaultPaths {
		s.Paths[k] = v
	}
	for _, name := range strings.Split(getenv("SENTINELA_LOGS"), ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "":
		case "nginx", "fail2ban", "ufw":
			s.Sources = append(s.Sources, name)
		default:
			return s, fmt.Errorf("SENTINELA_LOGS: fonte desconhecida %q (nginx|fail2ban|ufw)", name)
		}
	}
	for env, key := range map[string]string{
		"SENTINELA_LOG_NGINX_ACCESS_PATH": "nginx_access", "SENTINELA_LOG_NGINX_ERROR_PATH": "nginx_error",
		"SENTINELA_LOG_FAIL2BAN_PATH": "fail2ban", "SENTINELA_LOG_UFW_PATH": "ufw",
	} {
		if v := strings.TrimSpace(getenv(env)); v != "" {
			if !filepath.IsAbs(v) {
				return s, fmt.Errorf("%s deve ser um caminho absoluto", env)
			}
			s.Paths[key] = v
		}
	}
	s.NginxAll = getenv("SENTINELA_LOG_NGINX_ALL") == "true"
	s.FromStart = getenv("SENTINELA_LOG_FROM_START") == "true"
	dir := strings.TrimSpace(getenv("SENTINELA_STATE_DIR"))
	if dir == "" { // systemd (StateDirectory=) define STATE_DIRECTORY; pode haver vários separados por ':'
		dir, _, _ = strings.Cut(getenv("STATE_DIRECTORY"), ":")
	}
	if dir != "" {
		s.StateFile = filepath.Join(dir, "logtail.json")
	}
	return s, nil
}

// Build cria as fontes configuradas.
func (s Settings) Build(loc *time.Location) []*Source {
	st := LoadState(s.StateFile)
	mk := func(name, path string, p Parser) *Source {
		return &Source{Name: name, Path: path, Parser: p, State: st, FromStart: s.FromStart}
	}
	var out []*Source
	for _, name := range s.Sources {
		switch name {
		case "nginx":
			out = append(out,
				mk("nginx_access", s.Paths["nginx_access"], &NginxAccess{AllRequests: s.NginxAll, Loc: loc}),
				mk("nginx_error", s.Paths["nginx_error"], NginxError{Loc: loc}))
		case "fail2ban":
			out = append(out, mk("fail2ban", s.Paths["fail2ban"], Fail2ban{Loc: loc}))
		case "ufw":
			out = append(out, mk("ufw", s.Paths["ufw"], UFW{Loc: loc}))
		}
	}
	return out
}
