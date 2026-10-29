//go:build integration

package http_test

import (
	"testing"
	"time"
)

func TestSilencesAPI(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("srv-a")
	viewer, operator := e.newActor("viewer").mustLogin(), e.newActor("operator").mustLogin()
	ruleID := e.queryID(`SELECT id::text FROM alert_rules WHERE deleted_at IS NULL ORDER BY created_at LIMIT 1`)

	// viewer só lê; operador cria e cancela
	body := map[string]any{"reason": "deploy", "server_id": srv, "duration_minutes": 30}
	if r := viewer.do("POST", "/api/v1/silences", body); r.Status != 403 {
		t.Fatalf("viewer não cria: %d %s", r.Status, r.Raw)
	}
	r := operator.do("POST", "/api/v1/silences", body)
	if r.Status != 201 || r.Header.Get("Location") == "" {
		t.Fatalf("criar: %d %s", r.Status, r.Raw)
	}
	d := r.data()
	if d["status"] != "active" || d["kind"] != "silence" || d["server_name"] != "srv-a" || d["rule_id"] != nil || d["created_by"] != operator.Email {
		t.Errorf("silenciamento: %v", d)
	}
	id := d["id"].(string)

	if r := viewer.do("GET", "/api/v1/silences/"+id, nil); r.Status != 200 || r.data()["id"] != id {
		t.Errorf("viewer lê: %d %s", r.Status, r.Raw)
	}
	if r := viewer.do("DELETE", "/api/v1/silences/"+id, nil); r.Status != 403 {
		t.Errorf("viewer não cancela: %d", r.Status)
	}

	// agendada (manutenção futura) com regra
	start := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	r = operator.do("POST", "/api/v1/silences", map[string]any{"kind": "maintenance", "reason": "janela", "rule_id": ruleID, "starts_at": start, "ends_at": end})
	if r.Status != 201 || r.data()["status"] != "scheduled" || r.data()["rule_name"] == nil || r.data()["server_id"] != nil {
		t.Fatalf("agendar: %d %s", r.Status, r.Raw)
	}

	// filtros
	count := func(q string) int { return len(viewer.do("GET", "/api/v1/silences"+q, nil).list()) }
	if count("?status=active") != 1 || count("?status=scheduled") != 1 || count("?status=ended") != 0 || count("") != 2 {
		t.Errorf("filtros: active=%d scheduled=%d ended=%d all=%d", count("?status=active"), count("?status=scheduled"), count("?status=ended"), count(""))
	}
	if count("?server_id="+srv) != 2 { // a agendada vale para todos os servidores
		t.Errorf("server_id: %d", count("?server_id="+srv))
	}
	if r := viewer.do("GET", "/api/v1/silences?status=xyz", nil); r.Status != 422 {
		t.Errorf("status inválido: %d", r.Status)
	}

	// validação
	for name, b := range map[string]map[string]any{
		"sem motivo":         {"duration_minutes": 10},
		"sem fim":            {"reason": "x"},
		"servidor inexiste":  {"reason": "x", "duration_minutes": 10, "server_id": "11111111-1111-1111-1111-111111111111"},
		"regra inexistente":  {"reason": "x", "duration_minutes": 10, "rule_id": "11111111-1111-1111-1111-111111111111"},
		"muito longa":        {"reason": "x", "duration_minutes": 60 * 24 * 31},
		"campo desconhecido": {"reason": "x", "duration_minutes": 10, "foo": 1},
	} {
		if r := operator.do("POST", "/api/v1/silences", b); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}

	// cancelar é idempotente e some dos ativos
	for i := 0; i < 2; i++ {
		r := operator.do("DELETE", "/api/v1/silences/"+id, nil)
		if r.Status != 200 || r.data()["status"] != "cancelled" || r.data()["cancelled_by"] != operator.Email {
			t.Fatalf("cancelar #%d: %d %s", i, r.Status, r.Raw)
		}
	}
	if count("?status=active") != 0 || count("?status=ended") != 1 {
		t.Errorf("após cancelar: active=%d ended=%d", count("?status=active"), count("?status=ended"))
	}
	if r := operator.do("GET", "/api/v1/silences/11111111-1111-1111-1111-111111111111", nil); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}
	if r := operator.do("DELETE", "/api/v1/silences/xyz", nil); r.Status != 400 {
		t.Errorf("id inválido: %d", r.Status)
	}

	// auditoria
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE action = 'silence.create'`); n != 2 {
		t.Errorf("auditoria silence.create: %d", n)
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE action = 'silence.cancel'`); n != 1 {
		t.Errorf("auditoria silence.cancel (uma só, pois é idempotente): %d", n)
	}
}
