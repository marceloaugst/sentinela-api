//go:build integration

package http_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAgentDiscoveryFlow(t *testing.T) {
	e := newEnv(t, adminKey)
	a, b := e.createServer("srv-a"), e.createServer("srv-b")
	_, tok := e.issue(a, nil)

	// sem relatório: lista vazia, não é erro
	r := e.admin("GET", "/api/v1/servers/"+a+"/discovery", nil)
	if r.Status != 200 || len(r.data()["services"].([]any)) != 0 || r.data()["checked_at"] != nil {
		t.Fatalf("antes do relatório: %d %s", r.Status, r.Raw)
	}

	now := time.Now().UTC()
	rep := func(checked time.Time, fs ...map[string]any) map[string]any {
		out := make([]any, len(fs))
		for i, f := range fs {
			out[i] = f
		}
		return map[string]any{"checked_at": checked.Format(time.RFC3339Nano), "services": out}
	}
	r = e.do("POST", "/api/v1/agent/discovery", tok, rep(now,
		map[string]any{"key": "ssh", "status": "available", "source": "systemd", "unit": "ssh.service"},
		map[string]any{"key": "nginx", "status": "stopped", "unit": "nginx.service"},
		map[string]any{"key": "redis", "status": "not_found"}))
	if r.Status != 200 {
		t.Fatalf("relatório: %d %s", r.Status, r.Raw)
	}

	r = e.admin("GET", "/api/v1/servers/"+a+"/discovery", nil)
	d := r.data()
	sum := d["summary"].(map[string]any)
	if sum["total"] != float64(3) || sum["available"] != float64(1) || sum["unavailable"] != float64(2) {
		t.Errorf("resumo: %v", sum)
	}
	items := d["services"].([]any)
	if first := items[0].(map[string]any); first["key"] != "ssh" || first["available"] != true || first["action"] != "" {
		t.Errorf("ssh: %v", first)
	}
	if nginx := items[1].(map[string]any); !strings.Contains(nginx["action"].(string), "systemctl enable --now nginx.service") {
		t.Errorf("nginx: %v", nginx)
	}
	if redis := items[2].(map[string]any); !strings.Contains(redis["action"].(string), "docker run") {
		t.Errorf("redis: %v", redis)
	}

	// a descoberta é por servidor
	if n := len(e.admin("GET", "/api/v1/servers/"+b+"/discovery", nil).data()["services"].([]any)); n != 0 {
		t.Errorf("servidor b herdou %d itens", n)
	}
	if r := e.admin("GET", "/api/v1/servers/11111111-1111-1111-1111-111111111111/discovery", nil); r.Status != 404 {
		t.Errorf("servidor inexistente: %d", r.Status)
	}

	// vocabulário fechado: nada de chave, status ou unidade arbitrários
	for name, f := range map[string]map[string]any{
		"chave":   {"key": "mysql", "status": "not_found"},
		"status":  {"key": "ssh", "status": "ok"},
		"origem":  {"key": "ssh", "status": "available", "source": "bash"},
		"unidade": {"key": "ssh", "status": "stopped", "unit": "x; rm -rf /"},
	} {
		if r := e.do("POST", "/api/v1/agent/discovery", tok, rep(now, f)); r.Status != 422 {
			t.Errorf("%s inválido: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := e.do("POST", "/api/v1/agent/discovery", "", rep(now)); r.Status != 401 {
		t.Errorf("sem token: %d", r.Status)
	}
}

// A descoberta liga aos alertas: serviço visto disponível e depois parado abre alerta e incidente,
// sem nenhum cadastro manual (a regra service_down padrão vem da migração).
func TestDiscoveryFeedsAlerts(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("srv-a")
	_, tok := e.issue(srv, nil)
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id = $1`, srv)

	now := time.Now().UTC()
	send := func(at time.Time, fs ...map[string]any) {
		t.Helper()
		out := make([]any, len(fs))
		for i, f := range fs {
			out[i] = f
		}
		r := e.do("POST", "/api/v1/agent/discovery", tok, map[string]any{"checked_at": at.Format(time.RFC3339Nano), "services": out})
		if r.Status != 200 {
			t.Fatalf("relatório: %d %s", r.Status, r.Raw)
		}
	}
	ssh := func(status string) map[string]any {
		f := map[string]any{"key": "ssh", "status": status}
		if status == "available" {
			f["source"], f["unit"] = "systemd", "ssh.service"
		}
		return f
	}
	redis := map[string]any{"key": "redis", "status": "not_found"}

	send(now.Add(-10*time.Minute), ssh("available"), redis)
	// ssh virou serviço monitorado "up"; redis, que nunca existiu, não
	list := e.admin("GET", "/api/v1/servers/"+srv+"/services", nil).list()
	if len(list) != 1 {
		t.Fatalf("serviços monitorados: %v", list)
	}
	svc := list[0].(map[string]any)
	if svc["service_type"] != "discovered" || svc["status"] != "up" || svc["name"] != "SSH (automático)" {
		t.Fatalf("serviço descoberto: %v", svc)
	}
	// o agente não recebe lista de serviços para verificar: a API nunca lhe diz o que checar
	if cfg := e.do("GET", "/api/v1/agent/config", tok, nil).data(); cfg["services"] != nil || cfg["collect_interval_seconds"] == nil {
		t.Errorf("/agent/config: %v", cfg)
	}

	ev := e.evaluator()
	ev.HeartbeatTimeout = time.Hour
	tick := func(at time.Time) {
		t.Helper()
		ev.Now = func() time.Time { return at }
		if err := ev.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	tick(now.Add(-9 * time.Minute))
	if n := e.count(`SELECT count(*) FROM alerts`); n != 0 {
		t.Fatalf("serviço saudável não gera alerta: %d", n)
	}

	// ssh cai: pending, e só dispara após a duração da regra (120 s)
	send(now.Add(-5*time.Minute), ssh("stopped"), redis)
	if svc := e.admin("GET", "/api/v1/services/"+svc["id"].(string), nil).data(); svc["status"] != "down" || !strings.Contains(svc["last_error"].(string), "parado") {
		t.Fatalf("após parar: %v", svc)
	}
	tick(now.Add(-4 * time.Minute))
	if n := e.count(`SELECT count(*) FROM alerts WHERE status = 'firing'`); n != 0 {
		t.Fatalf("antes da duração mínima: %d alertas disparados", n)
	}
	tick(now.Add(-1 * time.Minute))
	if n := e.count(`SELECT count(*) FROM alerts WHERE status = 'firing'`); n != 1 {
		t.Fatalf("alerta não disparou: %d", n)
	}
	if n := e.count(`SELECT count(*) FROM incidents WHERE status = 'open'`); n != 1 {
		t.Fatalf("incidente não abriu: %d", n)
	}

	// volta a funcionar: alerta e incidente se resolvem (após recovery_seconds)
	send(now, ssh("available"), redis)
	tick(now.Add(10 * time.Second))
	tick(now.Add(2 * time.Minute))
	if n := e.count(`SELECT count(*) FROM incidents WHERE status = 'open'`); n != 0 {
		t.Errorf("incidente deveria estar resolvido: %d abertos", n)
	}

	// serviço removido (exclusão lógica) não é recriado
	e.exec(`UPDATE monitored_services SET deleted_at = now() WHERE id = $1`, svc["id"].(string))
	send(now.Add(time.Minute), ssh("available"), redis)
	if n := e.count(`SELECT count(*) FROM monitored_services WHERE deleted_at IS NULL AND server_id = $1`, srv); n != 0 {
		t.Errorf("serviço excluído foi recriado: %d", n)
	}
}
