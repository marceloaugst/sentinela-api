package collector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/services"
)

var unitNameRe = regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,128}$`)

// ServiceChecker executa as verificações locais pedidas pela API. Segurança: a API só informa
// QUAL serviço verificar; o agente decide COMO, com código próprio, e revalida cada alvo —
// nunca executa comandos e só conecta em loopback.
type ServiceChecker struct {
	CgroupRoot string // "/sys/fs/cgroup"
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	Stat       func(path string) (os.FileInfo, error)
}

func NewServiceChecker() *ServiceChecker {
	d := &net.Dialer{}
	return &ServiceChecker{CgroupRoot: "/sys/fs/cgroup", Dial: d.DialContext, Stat: os.Stat}
}

func ms(d time.Duration) *int { v := int(d.Milliseconds()); return &v }

// Check devolve ok=false quando o agente não consegue verificar o tipo neste host
// (ex.: sem cgroup v2). Nesse caso nada é reportado, evitando falso "down".
func (c *ServiceChecker) Check(ctx context.Context, s services.AgentService) (services.AgentResult, bool) {
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout < time.Second || timeout > 10*time.Second {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := services.AgentResult{ServiceID: s.ID}

	switch s.Type {
	case services.TypeTCP:
		host, port, ok := splitLoopback(s.Target)
		if !ok {
			res.Status, res.Error = services.StatusDown, "alvo tcp não permitido (somente loopback)"
			return res, true
		}
		start := time.Now()
		conn, err := c.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			res.Status, res.Error = services.StatusDown, "conexão recusada ou tempo limite excedido"
			return res, true
		}
		conn.Close()
		res.Status, res.LatencyMS = services.StatusUp, ms(time.Since(start))
		return res, true

	case services.TypeSystemd:
		if !unitNameRe.MatchString(s.Target) {
			res.Status, res.Error = services.StatusDown, "nome de unidade inválido"
			return res, true
		}
		if _, err := c.Stat(filepath.Join(c.CgroupRoot, "cgroup.controllers")); err != nil {
			return res, false // cgroup v2 indisponível: não sabemos verificar
		}
		unit := services.NormalizeUnit(s.Target)
		// Uma unidade em execução possui um cgroup próprio em system.slice.
		if _, err := c.Stat(filepath.Join(c.CgroupRoot, "system.slice", unit)); err != nil {
			res.Status, res.Error = services.StatusDown, "unidade sem processos em execução"
			return res, true
		}
		res.Status = services.StatusUp
		return res, true
	}
	return res, false
}

func splitLoopback(target string) (string, int, bool) {
	i := strings.LastIndex(target, ":")
	if i <= 0 {
		return "", 0, false
	}
	host := strings.Trim(target[:i], "[]")
	port, err := strconv.Atoi(target[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return host, port, true
	}
	return "", 0, false
}
