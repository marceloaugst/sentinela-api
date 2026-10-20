package collector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"sentinela/internal/services"
)

func TestTCPCheckLoopbackUpAndDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c := NewServiceChecker()
	r, ok := c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeTCP, Target: addr, TimeoutSeconds: 2})
	if !ok || r.Status != services.StatusUp || r.LatencyMS == nil {
		t.Errorf("up: %+v ok=%v", r, ok)
	}
	ln.Close()
	r, ok = c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeTCP, Target: addr, TimeoutSeconds: 2})
	if !ok || r.Status != services.StatusDown || r.Error == "" {
		t.Errorf("down: %+v", r)
	}
}

// Mesmo que a API (comprometida) mande um alvo externo, o agente recusa e NÃO conecta.
func TestTCPCheckRefusesNonLoopbackWithoutDialing(t *testing.T) {
	c := NewServiceChecker()
	dialed := false
	c.Dial = func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, net.ErrClosed }
	for _, target := range []string{"10.0.0.5:22", "169.254.169.254:80", "example.com:443", "8.8.8.8:53", "127.0.0.1", "0.0.0.0:80", "[::ffff:10.0.0.1]:80"} {
		r, ok := c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeTCP, Target: target, TimeoutSeconds: 1})
		if !ok || r.Status != services.StatusDown || r.Error == "" {
			t.Errorf("%s: %+v", target, r)
		}
	}
	if dialed {
		t.Error("o agente tentou conectar a um alvo não permitido")
	}
}

func TestSystemdCheckUsesCgroupWithoutExecutingAnything(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory"), 0o644)
	os.MkdirAll(filepath.Join(root, "system.slice", "nginx.service"), 0o755)
	c := NewServiceChecker()
	c.CgroupRoot = root

	r, ok := c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeSystemd, Target: "nginx"})
	if !ok || r.Status != services.StatusUp {
		t.Errorf("nginx deveria estar up: %+v", r)
	}
	r, _ = c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeSystemd, Target: "redis.service"})
	if r.Status != services.StatusDown {
		t.Errorf("redis deveria estar down: %+v", r)
	}
	// injeção: nome malicioso é recusado antes de qualquer acesso
	for _, evil := range []string{"nginx; rm -rf /", "../../etc/passwd", "$(id)", "a b"} {
		r, ok := c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeSystemd, Target: evil})
		if !ok || r.Status != services.StatusDown || r.Error != "nome de unidade inválido" {
			t.Errorf("%q: %+v", evil, r)
		}
	}
}

func TestSystemdCheckSkippedWithoutCgroupV2(t *testing.T) {
	c := NewServiceChecker()
	c.CgroupRoot = t.TempDir() // sem cgroup.controllers
	if _, ok := c.Check(context.Background(), services.AgentService{ID: "a", Type: services.TypeSystemd, Target: "nginx"}); ok {
		t.Error("sem cgroup v2 o agente não deve reportar (evita falso down)")
	}
	if _, ok := c.Check(context.Background(), services.AgentService{ID: "a", Type: "http", Target: "http://x"}); ok {
		t.Error("tipos centrais não são verificados pelo agente")
	}
}
