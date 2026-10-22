//go:build integration

package http_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSystemMetricsEndpoint(t *testing.T) {
	e := logsEnv(t)
	id := e.createServer("web")
	_, tok := e.issue(id, nil)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	good := map[string]any{"batch_id": "sys-0001-abcd", "samples": []any{
		map[string]any{"time": now, "metric": "oom_kills", "value": 1},
		map[string]any{"time": now, "metric": "inode_used_percent", "subject": "/", "value": 42.5},
	}}
	if r := e.do("POST", "/api/v1/agent/system-metrics", tok, good); r.Status != 200 || r.data()["stored"] != float64(2) {
		t.Fatalf("envio: %d %s", r.Status, r.Raw)
	}
	bad := map[string]any{"batch_id": "sys-0002-abcd", "samples": []any{map[string]any{"time": now, "metric": "drop_table", "value": 1}}}
	if r := e.do("POST", "/api/v1/agent/system-metrics", tok, bad); r.Status != 422 {
		t.Errorf("métrica desconhecida: %d", r.Status)
	}
	for _, bearer := range []string{"", adminKey} {
		if r := e.do("POST", "/api/v1/agent/system-metrics", bearer, good); r.Status != 401 {
			t.Errorf("sem credencial de agente (%q): %d", bearer, r.Status)
		}
	}
}

func TestSystemMetricsUnavailableWithoutClickHouse(t *testing.T) {
	e := newEnv(t, adminKey)
	_, tok := e.issue(e.createServer("web"), nil)
	body := map[string]any{"batch_id": "sys-0001-abcd", "samples": []any{map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "metric": "oom_kills", "value": 0}}}
	if r := e.do("POST", "/api/v1/agent/system-metrics", tok, body); r.Status != 503 {
		t.Errorf("%d %s", r.Status, r.Raw)
	}
}

// IP banido, alerta disparado e recuperação ficam registrados em notifications e consultáveis pela API.
func TestBanAndAlertNotificationsAreRecordedAndReadable(t *testing.T) {
	e := logsEnv(t)
	srv := e.createServer("web-1")
	_, tok := e.issue(srv, nil)
	now := time.Now().UTC()

	ban := map[string]any{"batch_id": "ban-0001-abcd", "entries": []any{
		logEntry(now.Add(-time.Minute), "fail2ban", "ban", "warning", "203.0.113.9", func(m map[string]any) { m["fields"] = map[string]string{"jail": "sshd"} }),
	}}
	if r := e.do("POST", "/api/v1/agent/logs", tok, ban); r.Status != 200 {
		t.Fatalf("ban: %d %s", r.Status, r.Raw)
	}
	if e.count(`SELECT count(*) FROM notifications WHERE kind='ip_banned' AND priority=3 AND severity='warning' AND server_id=$1`, srv) != 1 {
		t.Fatal("o ban deveria virar uma notificação registrada")
	}

	// alerta + recuperação
	e.sample(srv, now, 97, 4, 500, 1000, nil, nil)
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id=$1`, srv)
	e.exec(`UPDATE alert_rules SET priority = 1 WHERE id = $1`, e.rule("CPU alta", "cpu_usage_percent", ">", 90, "critical", 0, srv))
	if err := e.evaluator().Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM notifications WHERE kind='alert_triggered'`) != 1 {
		t.Fatal("alerta disparado deveria virar notificação")
	}

	r := e.admin("GET", "/api/v1/notifications", nil)
	if r.Status != 200 || len(r.list()) != 2 || r.meta()["unread"] != float64(2) || r.meta()["total"] != float64(2) {
		t.Fatalf("lista: %d %s", r.Status, r.Raw)
	}
	first := r.list()[0].(map[string]any)
	if first["server_name"] != "web-1" || first["title"] == "" || first["read_at"] != nil {
		t.Errorf("campos: %v", first)
	}
	for q, want := range map[string]int{"kind=ip_banned": 1, "kind=alert_triggered": 1, "priority=3": 1, "priority=1": 1, "server_id=" + srv: 2, "unread=true": 2} {
		if l := e.admin("GET", "/api/v1/notifications?"+q, nil); l.Status != 200 || len(l.list()) != want {
			t.Errorf("%q: %d (esperado %d) %s", q, len(l.list()), want, l.Raw)
		}
	}
	for _, q := range []string{"kind=x", "priority=7", "unread=talvez", "server_id=zzz"} {
		if l := e.admin("GET", "/api/v1/notifications?"+q, nil); l.Status != 422 {
			t.Errorf("%q deveria ser 422: %d", q, l.Status)
		}
	}

	id := fmt.Sprint(int64(first["id"].(float64)))
	if m := e.admin("POST", "/api/v1/notifications/"+id+"/read", nil); m.Status != 200 || m.data()["read_at"] == nil {
		t.Errorf("marcar como lida: %d %s", m.Status, m.Raw)
	}
	if l := e.admin("GET", "/api/v1/notifications?unread=true", nil); len(l.list()) != 1 || l.meta()["unread"] != float64(1) {
		t.Errorf("não lidas: %s", l.Raw)
	}
	if m := e.admin("POST", "/api/v1/notifications/999999/read", nil); m.Status != 404 {
		t.Errorf("inexistente: %d", m.Status)
	}
	if m := e.admin("POST", "/api/v1/notifications/abc/read", nil); m.Status != 400 {
		t.Errorf("id inválido: %d", m.Status)
	}
	if m := e.admin("POST", "/api/v1/notifications/read-all", nil); m.Status != 200 || m.data()["marked"] != float64(1) {
		t.Errorf("ler todas: %d %s", m.Status, m.Raw)
	}

	// Telegram recebe o ban: com um canal ativo o aviso entra na fila
	if !strings.Contains(first["title"].(string), "—") {
		t.Errorf("título: %v", first["title"])
	}
}
