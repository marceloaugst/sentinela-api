//go:build integration

package http_test

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	apphttp "sentinela/internal/http"
	"sentinela/internal/logs"
	"sentinela/internal/logstore"
)

// logsEnv sobe a API com o armazenamento de logs apontando para um ClickHouse real (TEST_CLICKHOUSE_URL).
func logsEnv(t *testing.T) *env {
	t.Helper()
	url := os.Getenv("TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("TEST_CLICKHOUSE_URL não definida")
	}
	e := newEnv(t, adminKey)
	st, err := logstore.New(logstore.Config{URL: url, Database: "sentinela_test_http", User: "default",
		Password: os.Getenv("TEST_CLICKHOUSE_PASSWORD"), RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.srv.Close()
	e.srv = httptest.NewServer(apphttp.NewRouter(apphttp.Deps{
		Config: e.cfg, Log: e.log, Metrics: e.metrics, DB: e.pool, Pool: e.pool, Hub: e.hub, Auth: e.auth,
		Registry: e.reg, Logs: st, Version: "test",
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func logEntry(at time.Time, source, typ, sev, ip string, mut ...func(map[string]any)) map[string]any {
	m := map[string]any{"time": at.UTC().Format(time.RFC3339Nano), "source": source, "type": typ, "severity": sev, "ip": ip}
	for _, f := range mut {
		f(m)
	}
	return m
}

func TestLogsDisabledWithoutClickHouse(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	_, tok := e.issue(id, nil)
	if r := e.admin("GET", "/api/v1/logs", nil); r.Status != 503 || r.errCode() != "LOGS_UNAVAILABLE" {
		t.Errorf("consulta: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("GET", "/api/v1/logs/stats", nil); r.Status != 503 {
		t.Errorf("stats: %d", r.Status)
	}
	body := map[string]any{"batch_id": "lote-0001-abcd", "entries": []any{logEntry(time.Now(), "fail2ban", "ban", "warning", "203.0.113.9")}}
	if r := e.do("POST", "/api/v1/agent/logs", tok, body); r.Status != 503 {
		t.Errorf("ingestão: %d %s", r.Status, r.Raw)
	}
}

func TestLogsIngestQueryAndBanEvent(t *testing.T) {
	e := logsEnv(t)
	srvA, srvB := e.createServer("web-a"), e.createServer("web-b")
	_, tokA := e.issue(srvA, nil)
	_, tokB := e.issue(srvB, nil)
	sse := e.stream("?types=security.ip_banned", nil)

	now := time.Now().UTC()
	batch := map[string]any{"batch_id": "lote-0001-abcd", "entries": []any{
		logEntry(now.Add(-2*time.Minute), "fail2ban", "ban", "warning", "203.0.113.9", func(m map[string]any) { m["fields"] = map[string]string{"jail": "sshd"} }),
		logEntry(now.Add(-time.Minute), "firewall", "block", "warning", "203.0.113.9", func(m map[string]any) { m["port"] = 22; m["raw"] = "[UFW BLOCK] SRC=203.0.113.9 DPT=22" }),
		logEntry(now, "nginx", "access", "warning", "198.51.100.7", func(m map[string]any) { m["status"] = 404 }),
	}}
	r := e.do("POST", "/api/v1/agent/logs", tokA, batch)
	if r.Status != 200 || r.data()["stored"].(float64) != 3 || r.data()["duplicate"] != false {
		t.Fatalf("ingestão: %d %s", r.Status, r.Raw)
	}
	ev := sse.expect("security.ip_banned").payload(t)
	if ev["ip"] != "203.0.113.9" || ev["jail"] != "sshd" {
		t.Errorf("evento de ban: %+v", ev)
	}

	// reenvio do mesmo lote: idempotente e sem novo evento
	if r := e.do("POST", "/api/v1/agent/logs", tokA, batch); r.Status != 200 || r.data()["duplicate"] != true {
		t.Errorf("reenvio: %d %s", r.Status, r.Raw)
	}
	select {
	case m := <-sse.msgs:
		t.Errorf("reenvio não deve anunciar de novo: %+v", m)
	case <-time.After(300 * time.Millisecond):
	}

	// o servidor B grava um registro próprio
	if r := e.do("POST", "/api/v1/agent/logs", tokB, map[string]any{"batch_id": "lote-0002-abcd",
		"entries": []any{logEntry(now, "nginx", "error", "error", "")}}); r.Status != 200 {
		t.Fatalf("servidor B: %d %s", r.Status, r.Raw)
	}

	q := "?server_id=" + srvA
	if r := e.admin("GET", "/api/v1/logs"+q, nil); r.Status != 200 || len(r.list()) != 3 || r.meta()["total"].(float64) != 3 {
		t.Fatalf("lista A: %d %s", r.Status, r.Raw)
	}
	l := e.admin("GET", "/api/v1/logs?server_id="+srvA+"&source=firewall&ip=203.0.113.9", nil).list()
	if len(l) != 1 || l[0].(map[string]any)["port"].(float64) != 22 || l[0].(map[string]any)["server_id"] != srvA {
		t.Errorf("filtro: %+v", l)
	}
	if r := e.admin("GET", "/api/v1/logs?server_id="+srvB, nil); len(r.list()) != 1 {
		t.Errorf("isolamento entre servidores: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/logs?server_id="+srvA+"&q=dpt%3D22", nil); len(r.list()) != 1 {
		t.Errorf("busca: %s", r.Raw)
	}

	st := e.admin("GET", "/api/v1/logs/stats"+q, nil)
	if st.Status != 200 || len(st.data()["top_ips"].([]any)) != 2 {
		t.Errorf("stats: %d %s", st.Status, st.Raw)
	}
}

func TestLogsValidationAndAuthorization(t *testing.T) {
	e := logsEnv(t)
	id := e.createServer("web")
	_, tok := e.issue(id, nil)
	now := time.Now().UTC()
	ok := logEntry(now, "nginx", "access", "info", "203.0.113.9")

	bad := []struct {
		name string
		body any
	}{
		{"batch_id curto", map[string]any{"batch_id": "x", "entries": []any{ok}}},
		{"sem entradas", map[string]any{"batch_id": "lote-0003-abcd", "entries": []any{}}},
		{"fonte desconhecida", map[string]any{"batch_id": "lote-0003-abcd", "entries": []any{logEntry(now, "apache", "access", "info", "")}}},
		{"tipo de outra fonte", map[string]any{"batch_id": "lote-0003-abcd", "entries": []any{logEntry(now, "nginx", "ban", "info", "")}}},
		{"ip inválido", map[string]any{"batch_id": "lote-0003-abcd", "entries": []any{logEntry(now, "nginx", "access", "info", "999.1.1.1")}}},
		{"muito antigo", map[string]any{"batch_id": "lote-0003-abcd", "entries": []any{logEntry(now.AddDate(0, 0, -60), "nginx", "access", "info", "")}}},
		{"futuro", map[string]any{"batch_id": "lote-0003-abcd", "entries": []any{logEntry(now.Add(time.Hour), "nginx", "access", "info", "")}}},
		{"server_id no corpo", map[string]any{"batch_id": "lote-0003-abcd", "server_id": id, "entries": []any{ok}}},
	}
	for _, c := range bad {
		if r := e.do("POST", "/api/v1/agent/logs", tok, c.body); r.Status != 422 && r.Status != 400 {
			t.Errorf("%s: %d %s", c.name, r.Status, r.Raw)
		}
	}
	big := make([]any, 501)
	for i := range big {
		big[i] = ok
	}
	if r := e.do("POST", "/api/v1/agent/logs", tok, map[string]any{"batch_id": "lote-0004-abcd", "entries": big}); r.Status != 422 {
		t.Errorf("lote grande: %d", r.Status)
	}

	// caracteres de controle e query string no raw são tratados na borda
	dirty := logEntry(now, "nginx", "access", "info", "203.0.113.9", func(m map[string]any) { m["raw"] = "GET /x\x1b[31m\r\nINJETADO" })
	if r := e.do("POST", "/api/v1/agent/logs", tok, map[string]any{"batch_id": "lote-0005-abcd", "entries": []any{dirty}}); r.Status != 200 {
		t.Fatalf("lote sujo: %d %s", r.Status, r.Raw)
	}
	rows := e.admin("GET", "/api/v1/logs?server_id="+id+"&q=INJETADO", nil).list()
	if len(rows) != 1 || strings.ContainsAny(rows[0].(map[string]any)["raw"].(string), "\x1b\r\n") {
		t.Errorf("raw deveria estar sem caracteres de controle: %+v", rows)
	}

	// autorização
	if r := e.do("POST", "/api/v1/agent/logs", "", map[string]any{"batch_id": "lote-0006-abcd", "entries": []any{ok}}); r.Status != 401 {
		t.Errorf("sem credencial: %d", r.Status)
	}
	if r := e.do("GET", "/api/v1/logs", tok, nil); r.Status != 401 {
		t.Errorf("token de agente não lê logs: %d", r.Status)
	}
	if r := e.do("GET", "/api/v1/logs", "", nil); r.Status != 401 {
		t.Errorf("anônimo: %d", r.Status)
	}
	viewer := e.newActor("viewer").mustLogin()
	if r := viewer.do("GET", "/api/v1/logs?per_page=5", nil); r.Status != 200 {
		t.Errorf("viewer deve ler: %d %s", r.Status, r.Raw)
	}
	for _, q := range []string{"?source=apache", "?severity=x", "?ip=1.1.1", "?server_id=abc", "?from=ontem", "?per_page=1000",
		"?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z"} {
		if r := viewer.do("GET", "/api/v1/logs"+q, nil); r.Status != 422 {
			t.Errorf("%s: %d %s", q, r.Status, r.Raw)
		}
	}
	// o valor de busca vai como parâmetro, nunca como SQL
	if r := viewer.do("GET", "/api/v1/logs?q=%27%3B%20DROP%20TABLE%20x%3B%20--", nil); r.Status != 200 || len(r.list()) != 0 {
		t.Errorf("injeção: %d %s", r.Status, r.Raw)
	}
	_ = logs.SourceNginx
}
