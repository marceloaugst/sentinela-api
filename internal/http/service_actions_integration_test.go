//go:build integration

package http_test

import (
	"testing"
	"time"
)

// Fluxo completo: operador pede, o agente busca e responde, e a auditoria mostra quem deu o comando.
func TestServiceActionsFlow(t *testing.T) {
	e := newEnv(t, adminKey)
	admin := e.newActor("admin").mustLogin()
	op := e.newActor("operator").mustLogin()
	viewer := e.newActor("viewer").mustLogin()
	a, b := e.createServer("srv-a"), e.createServer("srv-b")
	_, tokA := e.issue(a, nil)
	_, tokB := e.issue(b, nil)

	report := e.do("POST", "/api/v1/agent/discovery", tokA, map[string]any{
		"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
		"services": []any{
			map[string]any{"key": "nginx", "status": "available", "source": "systemd", "unit": "nginx.service"},
			map[string]any{"key": "ssh", "status": "available", "source": "systemd", "unit": "ssh.service"},
			map[string]any{"key": "redis", "status": "available", "source": "docker"},
			map[string]any{"key": "cron", "status": "stopped", "unit": "cron.service"},
		}})
	if report.Status != 200 {
		t.Fatalf("relatório: %d %s", report.Status, report.Raw)
	}

	// O frontend descobre o que oferecer em "actions".
	acts := map[string][]any{}
	for _, it := range admin.do("GET", "/api/v1/servers/"+a+"/discovery", nil).data()["services"].([]any) {
		m := it.(map[string]any)
		acts[m["key"].(string)] = m["actions"].([]any)
	}
	if len(acts["nginx"]) != 2 || len(acts["ssh"]) != 1 || acts["ssh"][0] != "restart" || len(acts["redis"]) != 0 || len(acts["cron"]) != 1 || acts["cron"][0] != "start" {
		t.Fatalf("actions: %v", acts)
	}

	path := "/api/v1/servers/" + a + "/services/nginx/actions"
	if r := viewer.do("POST", path, map[string]string{"action": "restart"}); r.Status != 403 {
		t.Errorf("viewer não pode: %d", r.Status)
	}
	for name, body := range map[string]any{"vazio": map[string]string{}, "ação inválida": map[string]string{"action": "disable"}, "campo extra": map[string]string{"action": "stop", "unit": "x"}} {
		if r := op.do("POST", path, body); r.Status != 422 && r.Status != 400 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/services/mysql/actions", map[string]string{"action": "stop"}); r.Status != 404 {
		t.Errorf("serviço fora do catálogo: %d", r.Status)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/services/ssh/actions", map[string]string{"action": "stop"}); r.Status != 422 || r.errCode() != "ACTION_NOT_ALLOWED" {
		t.Errorf("parar o ssh: %d %s", r.Status, r.Raw)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/services/redis/actions", map[string]string{"action": "restart"}); r.Status != 422 {
		t.Errorf("container: %d", r.Status)
	}

	r := op.do("POST", path, map[string]string{"action": "restart"})
	if r.Status != 202 || r.data()["status"] != "pending" || r.data()["requested_by"] != op.ID || r.data()["requested_actor"] != op.Email {
		t.Fatalf("pedido: %d %s", r.Status, r.Raw)
	}
	id := r.data()["id"].(string)
	if r := op.do("POST", path, map[string]string{"action": "stop"}); r.Status != 409 || r.errCode() != "COMMAND_IN_PROGRESS" {
		t.Errorf("segundo pedido: %d %s", r.Status, r.Raw)
	}

	// O agente do outro servidor não vê nem conclui o comando; sem token, nada.
	if r := e.do("GET", "/api/v1/agent/commands", tokB, nil); r.Status != 200 || len(r.list()) != 0 {
		t.Errorf("agente de outro servidor: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/api/v1/agent/commands", "", nil); r.Status != 401 {
		t.Errorf("sem token: %d", r.Status)
	}
	if r := e.do("POST", "/api/v1/agent/commands/"+id+"/result", tokB, map[string]string{"status": "succeeded"}); r.Status != 404 {
		t.Errorf("outro servidor concluiu: %d", r.Status)
	}

	// O agente recebe só (chave, ação): nunca unidade nem comando.
	got := e.do("GET", "/api/v1/agent/commands", tokA, nil)
	list := got.list()
	if got.Status != 200 || len(list) != 1 {
		t.Fatalf("agente: %d %s", got.Status, got.Raw)
	}
	cmd := list[0].(map[string]any)
	if cmd["id"] != id || cmd["service_key"] != "nginx" || cmd["action"] != "restart" || len(cmd) != 3 {
		t.Errorf("payload do agente: %v", cmd)
	}
	if r := e.do("POST", "/api/v1/agent/commands/"+id+"/result", tokA, map[string]string{"status": "talvez"}); r.Status != 422 {
		t.Errorf("status inválido: %d", r.Status)
	}
	if r := e.do("POST", "/api/v1/agent/commands/"+id+"/result", tokA, map[string]string{"status": "succeeded", "message": "systemctl restart nginx.service"}); r.Status != 200 {
		t.Fatalf("resultado: %d %s", r.Status, r.Raw)
	}
	if r := e.do("POST", "/api/v1/agent/commands/"+id+"/result", tokA, map[string]string{"status": "failed"}); r.Status != 409 {
		t.Errorf("resultado repetido: %d", r.Status)
	}

	done := viewer.do("GET", "/api/v1/service-commands/"+id, nil)
	if done.Status != 200 || done.data()["status"] != "succeeded" || done.data()["requested_actor"] != op.Email {
		t.Errorf("comando final: %d %s", done.Status, done.Raw)
	}
	if l := viewer.do("GET", "/api/v1/servers/"+a+"/service-commands", nil); l.Status != 200 || len(l.list()) != 1 {
		t.Errorf("lista: %d %s", l.Status, l.Raw)
	}

	// A tela de Auditoria (admin) mostra quem deu o comando.
	logs := admin.do("GET", "/api/v1/audit-logs?action=service.&resource_id="+a, nil)
	seen := map[string]map[string]any{}
	for _, it := range logs.list() {
		m := it.(map[string]any)
		seen[m["action"].(string)] = m
	}
	if m := seen["service.restart"]; m == nil || m["actor"] != op.Email || m["actor_user_id"] != op.ID {
		t.Errorf("auditoria do pedido: %v", seen)
	}
	if m := seen["service.result"]; m == nil || m["actor"] != "agente" {
		t.Errorf("auditoria do resultado: %v", seen)
	}
}
