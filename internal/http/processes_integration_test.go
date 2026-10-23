//go:build integration

package http_test

import (
	"strings"
	"testing"
	"time"
)

// Fluxo: o agente informa os processos, a tela lista/filtra/ordena e o operador encerra só os permitidos.
func TestProcessesFlow(t *testing.T) {
	e := newEnv(t, adminKey)
	admin := e.newActor("admin").mustLogin()
	op := e.newActor("operator").mustLogin()
	viewer := e.newActor("viewer").mustLogin()
	a, b := e.createServer("srv-a"), e.createServer("srv-b")
	_, tokA := e.issue(a, nil)
	_, tokB := e.issue(b, nil)

	if r := viewer.do("GET", "/api/v1/servers/"+a+"/processes", nil); r.Status != 200 || r.data()["status"] != "unknown" {
		t.Fatalf("sem relatório: %d %s", r.Status, r.Raw)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	proc := func(pid, start int, name, cmd, user, restriction string, cpu float64, mem int64) map[string]any {
		return map[string]any{"pid": pid, "start_time": start, "ppid": 1, "name": name, "cmdline": cmd, "user": user, "state": "S",
			"threads": 1, "cpu_percent": cpu, "memory_bytes": mem, "restriction": restriction}
	}
	nginx := proc(200, 2000, "nginx", "nginx: master", "root", "service", 1.5, 50<<20)
	nginx["service_key"] = "nginx"
	body := map[string]any{"checked_at": now, "cpus": 4, "memory_total_bytes": 1 << 30, "total": 40, "processes": []any{
		proc(100, 1000, "worker", "worker --password=***", "sentinela", "", 80.5, 200<<20),
		nginx,
		proc(300, 3000, "postgres", "postgres: main", "postgres", "other_user", 10, 300<<20),
	}}

	for name, bad := range map[string]func(map[string]any){
		"cpus":      func(m map[string]any) { m["cpus"] = 0 },
		"restrição": func(m map[string]any) { m["processes"].([]any)[0].(map[string]any)["restriction"] = "x" },
		"duplicado": func(m map[string]any) { m["processes"].([]any)[1].(map[string]any)["pid"] = 100 },
	} {
		cp := map[string]any{}
		for k, v := range body {
			cp[k] = v
		}
		ps := []any{}
		for _, p := range body["processes"].([]any) {
			m := map[string]any{}
			for k, v := range p.(map[string]any) {
				m[k] = v
			}
			ps = append(ps, m)
		}
		cp["processes"] = ps
		bad(cp)
		if r := e.do("POST", "/api/v1/agent/processes", tokA, cp); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := e.do("POST", "/api/v1/agent/processes", "", body); r.Status != 401 {
		t.Errorf("sem token: %d", r.Status)
	}
	if r := e.do("POST", "/api/v1/agent/processes", tokA, body); r.Status != 200 {
		t.Fatalf("relatório: %d %s", r.Status, r.Raw)
	}
	// relatório mais antigo não sobrescreve
	old := map[string]any{"checked_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), "cpus": 4, "processes": []any{}}
	e.do("POST", "/api/v1/agent/processes", tokA, old)

	got := viewer.do("GET", "/api/v1/servers/"+a+"/processes", nil)
	if got.Status != 200 || got.data()["status"] != "ok" || got.data()["total"] != 40.0 || got.data()["matched"] != 3.0 {
		t.Fatalf("lista: %d %s", got.Status, got.Raw)
	}
	list := got.data()["processes"].([]any)
	first := list[0].(map[string]any)
	if first["name"] != "worker" || first["memory_percent"] != 19.5 || len(first["actions"].([]any)) != 2 {
		t.Errorf("primeiro (maior CPU): %v", first)
	}
	byName := map[string]map[string]any{}
	for _, p := range list {
		m := p.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["nginx"]["service_name"] != "Nginx" || len(byName["nginx"]["actions"].([]any)) != 0 || byName["nginx"]["restriction_message"] == "" {
		t.Errorf("nginx: %v", byName["nginx"])
	}

	// ordenação, filtro e limite
	byMem := viewer.do("GET", "/api/v1/servers/"+a+"/processes?sort=memory&limit=1", nil)
	if l := byMem.data()["processes"].([]any); len(l) != 1 || l[0].(map[string]any)["name"] != "postgres" || byMem.data()["matched"] != 3.0 {
		t.Errorf("sort=memory: %s", byMem.Raw)
	}
	if q := viewer.do("GET", "/api/v1/servers/"+a+"/processes?q=NGINX", nil); len(q.data()["processes"].([]any)) != 1 {
		t.Errorf("q: %s", q.Raw)
	}
	for _, qs := range []string{"sort=x", "limit=0", "limit=501", "limit=abc"} {
		if r := viewer.do("GET", "/api/v1/servers/"+a+"/processes?"+qs, nil); r.Status != 422 {
			t.Errorf("%s: %d", qs, r.Status)
		}
	}
	if r := viewer.do("GET", "/api/v1/servers/"+b+"/processes", nil); r.data()["status"] != "unknown" {
		t.Errorf("isolamento entre servidores: %s", r.Raw)
	}

	// encerrar
	path := "/api/v1/servers/" + a + "/processes/100/actions"
	term := map[string]any{"action": "terminate", "start_time": 1000}
	if r := viewer.do("POST", path, term); r.Status != 403 {
		t.Errorf("viewer não pode: %d", r.Status)
	}
	if r := op.do("POST", path, map[string]any{"action": "reboot", "start_time": 1000}); r.Status != 422 {
		t.Errorf("ação inválida: %d", r.Status)
	}
	if r := op.do("POST", path, map[string]any{"action": "kill"}); r.Status != 422 {
		t.Errorf("sem start_time: %d", r.Status)
	}
	if r := op.do("POST", path, map[string]any{"action": "kill", "start_time": 999}); r.Status != 404 {
		t.Errorf("start_time de outro processo (pid reaproveitado): %d", r.Status)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/processes/200/actions", map[string]any{"action": "kill", "start_time": 2000}); r.Status != 422 || r.errCode() != "ACTION_NOT_ALLOWED" {
		t.Errorf("serviço: %d %s", r.Status, r.Raw)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/processes/300/actions", map[string]any{"action": "kill", "start_time": 3000}); r.Status != 422 {
		t.Errorf("outro usuário: %d", r.Status)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/processes/1/actions", term); r.Status != 404 {
		t.Errorf("pid 1: %d", r.Status)
	}
	if r := op.do("POST", "/api/v1/servers/"+b+"/processes/100/actions", term); r.Status != 404 {
		t.Errorf("processo de outro servidor: %d", r.Status)
	}

	r := op.do("POST", path, term)
	if r.Status != 202 || r.data()["target"] != "100:1000" || r.data()["unit"] != "worker" || r.data()["service_key"] != "process" ||
		r.data()["service_name"] != "Processo worker" || r.data()["requested_actor"] != op.Email {
		t.Fatalf("pedido: %d %s", r.Status, r.Raw)
	}
	id := r.data()["id"].(string)
	if r := op.do("POST", path, map[string]any{"action": "kill", "start_time": 1000}); r.Status != 409 || r.errCode() != "COMMAND_IN_PROGRESS" {
		t.Errorf("segundo pedido: %d %s", r.Status, r.Raw)
	}

	if r := e.do("GET", "/api/v1/agent/commands", tokB, nil); len(r.list()) != 0 {
		t.Errorf("agente de outro servidor: %s", r.Raw)
	}
	cmds := e.do("GET", "/api/v1/agent/commands", tokA, nil).list()
	if len(cmds) != 1 {
		t.Fatalf("comandos do agente: %v", cmds)
	}
	if c := cmds[0].(map[string]any); c["id"] != id || c["service_key"] != "process" || c["action"] != "terminate" || c["target"] != "100:1000" {
		t.Fatalf("comando entregue: %v", c)
	}
	if r := e.do("POST", "/api/v1/agent/commands/"+id+"/result", tokA, map[string]string{"status": "succeeded", "message": "worker (pid 100) encerrado com SIGTERM."}); r.Status != 200 {
		t.Fatalf("resultado: %d %s", r.Status, r.Raw)
	}
	if d := viewer.do("GET", "/api/v1/service-commands/"+id, nil); d.data()["status"] != "succeeded" {
		t.Errorf("comando: %s", d.Raw)
	}

	seen := map[string]bool{}
	for _, it := range admin.do("GET", "/api/v1/audit-logs?action=process.&resource_id="+a, nil).list() {
		m := it.(map[string]any)
		if m["actor"] == op.Email {
			seen[m["action"].(string)] = true
		}
	}
	if !seen["process.terminate"] {
		t.Errorf("auditoria: %v", seen)
	}
	if strings.Contains(viewer.do("GET", "/api/v1/servers/"+a+"/processes", nil).Raw, "hunter2") {
		t.Error("segredo vazou")
	}
}

// O histórico dos maiores consumidores: o agente envia, a API grava no ClickHouse e a tela consulta por janela.
func TestProcessHistory(t *testing.T) {
	e := logsEnv(t)
	viewer := e.newActor("viewer").mustLogin()
	a := e.createServer("srv-a")
	_, tokA := e.issue(a, nil)

	since := time.Now().UTC().Add(-time.Minute)
	if r := viewer.do("GET", "/api/v1/servers/"+a+"/processes/history", nil); r.Status != 200 || len(r.data()["samples"].([]any)) != 0 {
		t.Fatalf("sem histórico: %d %s", r.Status, r.Raw)
	}
	proc := func(pid int, name string, cpu float64, mem int64) map[string]any {
		return map[string]any{"pid": pid, "start_time": pid, "ppid": 1, "name": name, "cmdline": name, "user": "app", "state": "S",
			"threads": 1, "cpu_percent": cpu, "memory_bytes": mem, "restriction": ""}
	}
	send := func(at time.Time, ps ...any) {
		t.Helper()
		body := map[string]any{"checked_at": at.UTC().Format(time.RFC3339Nano), "cpus": 4, "memory_total_bytes": 1 << 30, "total": len(ps), "processes": ps}
		if r := e.do("POST", "/api/v1/agent/processes", tokA, body); r.Status != 200 {
			t.Fatalf("envio: %d %s", r.Status, r.Raw)
		}
	}
	t1 := time.Now().UTC().Add(-30 * time.Second)
	// 7 processos: só os 5 maiores por CPU e os 5 maiores por memória vão para o histórico (união de 6)
	send(t1,
		proc(10, "node", 90, 10<<20), proc(11, "a", 50, 1<<20), proc(12, "b", 40, 1<<20), proc(13, "c", 30, 1<<20), proc(14, "d", 20, 1<<20),
		proc(15, "mysql", 0, 900<<20), proc(16, "e", 0, 1<<20))
	send(t1.Add(10*time.Second), proc(10, "node", 95, 10<<20))

	r := viewer.do("GET", "/api/v1/servers/"+a+"/processes/history?from="+since.Format(time.RFC3339)+"&to="+time.Now().UTC().Add(time.Minute).Format(time.RFC3339), nil)
	if r.Status != 200 {
		t.Fatalf("histórico: %d %s", r.Status, r.Raw)
	}
	samples := r.data()["samples"].([]any)
	if len(samples) != 2 {
		t.Fatalf("leituras: %s", r.Raw)
	}
	first := samples[0].(map[string]any)["processes"].([]any)
	names := map[string]bool{}
	for _, p := range first {
		names[p.(map[string]any)["name"].(string)] = true
	}
	if len(first) != 6 || !names["node"] || !names["mysql"] || names["e"] {
		t.Errorf("1ª leitura: %v", names)
	}
	if first[0].(map[string]any)["name"] != "node" || first[0].(map[string]any)["cpu_percent"] != 90.0 {
		t.Errorf("ordem por CPU: %v", first[0])
	}
	// a linha de comando não vai para o histórico
	if strings.Contains(r.Raw, "cmdline") {
		t.Error("cmdline no histórico")
	}
	// reenvio da mesma leitura não duplica
	send(t1.Add(10*time.Second), proc(10, "node", 95, 10<<20))
	if r2 := viewer.do("GET", "/api/v1/servers/"+a+"/processes/history?from="+since.Format(time.RFC3339), nil); len(r2.data()["samples"].([]any)) != 2 {
		t.Errorf("duplicou: %s", r2.Raw)
	}

	for _, qs := range []string{"from=ontem", "to=x", "from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", "from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z"} {
		if r := viewer.do("GET", "/api/v1/servers/"+a+"/processes/history?"+qs, nil); r.Status != 422 {
			t.Errorf("%s: %d %s", qs, r.Status, r.Raw)
		}
	}
}

func TestProcessHistoryNeedsClickHouse(t *testing.T) {
	e := newEnv(t, adminKey)
	viewer := e.newActor("viewer").mustLogin()
	a := e.createServer("srv-a")
	if r := viewer.do("GET", "/api/v1/servers/"+a+"/processes/history", nil); r.Status != 503 || r.errCode() != "LOGS_UNAVAILABLE" {
		t.Errorf("sem ClickHouse: %d %s", r.Status, r.Raw)
	}
}
