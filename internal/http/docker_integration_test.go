//go:build integration

package http_test

import (
	"strings"
	"testing"
	"time"
)

// Fluxo: o agente informa o Docker, o operador reinicia/inicia containers e a tela vê erro e log dos inativos.
func TestDockerFlow(t *testing.T) {
	e := newEnv(t, adminKey)
	admin := e.newActor("admin").mustLogin()
	op := e.newActor("operator").mustLogin()
	viewer := e.newActor("viewer").mustLogin()
	a, b := e.createServer("srv-a"), e.createServer("srv-b")
	_, tokA := e.issue(a, nil)
	_, tokB := e.issue(b, nil)
	up, down := strings.Repeat("a", 64), strings.Repeat("b", 64)

	// Antes de qualquer relatório.
	if r := viewer.do("GET", "/api/v1/servers/"+a+"/docker", nil); r.Status != 200 || r.data()["status"] != "unknown" {
		t.Fatalf("sem relatório: %d %s", r.Status, r.Raw)
	}
	// Servidor sem Docker.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if r := e.do("POST", "/api/v1/agent/docker", tokB, map[string]any{"checked_at": now, "status": "not_installed", "message": "Docker não encontrado"}); r.Status != 200 {
		t.Fatalf("relatório sem docker: %d %s", r.Status, r.Raw)
	}
	if r := viewer.do("GET", "/api/v1/servers/"+b+"/docker", nil); r.data()["status"] != "not_installed" || len(r.data()["containers"].([]any)) != 0 {
		t.Errorf("not_installed: %s", r.Raw)
	}
	// Relatórios inválidos.
	for name, body := range map[string]any{
		"id curto":          map[string]any{"checked_at": now, "status": "ok", "containers": []any{map[string]any{"id": "abc", "state": "running"}}},
		"status":            map[string]any{"checked_at": now, "status": "x"},
		"containers sem ok": map[string]any{"checked_at": now, "status": "no_access", "containers": []any{map[string]any{"id": up, "state": "running"}}},
	} {
		if r := e.do("POST", "/api/v1/agent/docker", tokA, body); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := e.do("POST", "/api/v1/agent/docker", "", map[string]any{"checked_at": now, "status": "ok"}); r.Status != 401 {
		t.Errorf("sem token: %d", r.Status)
	}

	rep := e.do("POST", "/api/v1/agent/docker", tokA, map[string]any{"checked_at": now, "status": "ok", "containers": []any{
		map[string]any{"id": up, "name": "web", "image": "nginx", "state": "running", "status": "Up 3 hours"},
		map[string]any{"id": down, "name": "api", "image": "app:1", "state": "exited", "status": "Exited (1) 2 minutes ago",
			"exit_code": 1, "error": "Saiu com erro, código 1.", "log_tail": "Error: cannot connect to database\n"},
	}})
	if rep.Status != 200 {
		t.Fatalf("relatório: %d %s", rep.Status, rep.Raw)
	}
	// Um relatório mais antigo não sobrescreve o atual.
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	e.do("POST", "/api/v1/agent/docker", tokA, map[string]any{"checked_at": old, "status": "unavailable", "message": "velho"})

	got := viewer.do("GET", "/api/v1/servers/"+a+"/docker", nil)
	if got.Status != 200 || got.data()["status"] != "ok" {
		t.Fatalf("docker: %d %s", got.Status, got.Raw)
	}
	sum := got.data()["summary"].(map[string]any)
	if sum["total"] != 2.0 || sum["running"] != 1.0 || sum["stopped"] != 1.0 {
		t.Errorf("resumo: %v", sum)
	}
	byName := map[string]map[string]any{}
	for _, c := range got.data()["containers"].([]any) {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if acts := byName["web"]["actions"].([]any); len(acts) != 1 || acts[0] != "restart" {
		t.Errorf("ativo: %v", byName["web"])
	}
	if acts := byName["api"]["actions"].([]any); len(acts) != 1 || acts[0] != "start" ||
		byName["api"]["error"] != "Saiu com erro, código 1." || !strings.Contains(byName["api"]["log_tail"].(string), "cannot connect") {
		t.Errorf("inativo: %v", byName["api"])
	}

	path := "/api/v1/servers/" + a + "/docker/containers/" + up + "/actions"
	if r := viewer.do("POST", path, map[string]string{"action": "restart"}); r.Status != 403 {
		t.Errorf("viewer não pode: %d", r.Status)
	}
	if r := op.do("POST", path, map[string]string{"action": "stop"}); r.Status != 422 {
		t.Errorf("stop não existe: %d", r.Status)
	}
	if r := op.do("POST", path, map[string]string{"action": "start"}); r.Status != 422 || r.errCode() != "ACTION_NOT_ALLOWED" {
		t.Errorf("start em ativo: %d %s", r.Status, r.Raw)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/docker/containers/"+strings.Repeat("d", 64)+"/actions", map[string]string{"action": "restart"}); r.Status != 404 {
		t.Errorf("container desconhecido: %d", r.Status)
	}
	if r := op.do("POST", "/api/v1/servers/"+a+"/docker/containers/web/actions", map[string]string{"action": "restart"}); r.Status != 404 {
		t.Errorf("id inválido: %d", r.Status)
	}
	if r := op.do("POST", "/api/v1/servers/"+b+"/docker/containers/"+up+"/actions", map[string]string{"action": "restart"}); r.Status != 404 {
		t.Errorf("container de outro servidor: %d", r.Status)
	}

	r := op.do("POST", path, map[string]string{"action": "restart"})
	if r.Status != 202 || r.data()["target"] != up || r.data()["unit"] != "web" || r.data()["requested_actor"] != op.Email {
		t.Fatalf("pedido: %d %s", r.Status, r.Raw)
	}
	id := r.data()["id"].(string)
	if r := op.do("POST", path, map[string]string{"action": "restart"}); r.Status != 409 || r.errCode() != "COMMAND_IN_PROGRESS" {
		t.Errorf("segundo pedido: %d %s", r.Status, r.Raw)
	}
	// Outro container do mesmo servidor não é bloqueado.
	r2 := op.do("POST", "/api/v1/servers/"+a+"/docker/containers/"+down+"/actions", map[string]string{"action": "start"})
	if r2.Status != 202 {
		t.Fatalf("outro container: %d %s", r2.Status, r2.Raw)
	}
	id2 := r2.data()["id"].(string)

	// O agente de outro servidor não vê os comandos; o do servidor recebe o alvo.
	if r := e.do("GET", "/api/v1/agent/commands", tokB, nil); len(r.list()) != 0 {
		t.Errorf("agente de outro servidor: %s", r.Raw)
	}
	targets := map[string]string{}
	for _, c := range e.do("GET", "/api/v1/agent/commands", tokA, nil).list() {
		m := c.(map[string]any)
		targets[m["id"].(string)] = m["target"].(string)
	}
	if targets[id] != up || targets[id2] != down {
		t.Fatalf("comandos do agente: %v", targets)
	}
	if r := e.do("POST", "/api/v1/agent/commands/"+id+"/result", tokA, map[string]string{"status": "succeeded", "message": "docker restart web"}); r.Status != 200 {
		t.Fatalf("resultado: %d %s", r.Status, r.Raw)
	}
	e.do("POST", "/api/v1/agent/commands/"+id2+"/result", tokA, map[string]string{"status": "failed", "message": "O container api não ficou ativo: Saiu com erro, código 1."})
	if d := viewer.do("GET", "/api/v1/service-commands/"+id2, nil); d.data()["status"] != "failed" ||
		!strings.Contains(d.data()["message"].(string), "não ficou ativo") || d.data()["service_name"] != "Container api" {
		t.Errorf("comando com falha: %s", d.Raw)
	}

	seen := map[string]bool{}
	for _, it := range admin.do("GET", "/api/v1/audit-logs?action=docker.&resource_id="+a, nil).list() {
		m := it.(map[string]any)
		if m["actor"] == op.Email {
			seen[m["action"].(string)] = true
		}
	}
	if !seen["docker.restart"] || !seen["docker.start"] {
		t.Errorf("auditoria: %v", seen)
	}
}
