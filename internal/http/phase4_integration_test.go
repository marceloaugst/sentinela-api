//go:build integration

package http_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"sentinela/internal/alerts"
	"sentinela/internal/config"
)

const chatID = "-1001"
const botToken = "123456789:AAH-testtoken_abcdefghijklmnopqrstuvwxyz1234"

func withSecrets(c *config.Config) {
	c.SecretsKey = bytes.Repeat([]byte{9}, 32)
	c.TelegramAllowedChatIDs = []string{chatID}
}

func (e *env) post(path string, body any) resp { return e.admin("POST", path, body) }

func (e *env) evaluator() *alerts.Evaluator {
	return &alerts.Evaluator{Pool: e.pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatTimeout: 60 * time.Second}
}

func TestPhase4EndpointsRequireAdminKey(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	_, tok := e.issue(id, nil)
	zero := "00000000-0000-0000-0000-000000000000"
	reqs := [][2]string{
		{"GET", "/services"}, {"GET", "/services/" + zero}, {"GET", "/servers/" + id + "/services"},
		{"GET", "/servers/" + id + "/incidents"}, {"GET", "/alert-rules"}, {"POST", "/alert-rules"},
		{"GET", "/alert-rules/" + zero}, {"PATCH", "/alert-rules/" + zero}, {"DELETE", "/alert-rules/" + zero},
		{"GET", "/alerts"}, {"GET", "/alerts/" + zero}, {"POST", "/alerts/" + zero + "/acknowledge"},
		{"POST", "/alerts/" + zero + "/resolve"}, {"GET", "/incidents"}, {"GET", "/incidents/" + zero},
		{"GET", "/incidents/" + zero + "/events"}, {"GET", "/notification-channels"}, {"POST", "/notification-channels"},
		{"GET", "/notification-channels/" + zero}, {"PATCH", "/notification-channels/" + zero},
		{"DELETE", "/notification-channels/" + zero}, {"POST", "/notification-channels/" + zero + "/test"},
	}
	for _, rq := range reqs {
		for _, bearer := range []string{"", tok, "chave-errada"} {
			if r := e.do(rq[0], "/api/v1"+rq[1], bearer, nil); r.Status != 401 {
				t.Errorf("%s %s com credencial %q: %d (esperado 401)", rq[0], rq[1], bearer[:min(len(bearer), 6)], r.Status)
			}
		}
	}
}

func TestAlertRulesAPI(t *testing.T) {
	e := newEnv(t, adminKey)
	e.exec(`DELETE FROM alert_rules`) // a migração cria uma regra service_down padrão
	srv := e.createServer("web-1")

	body := map[string]any{"name": "CPU alta", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 90, "severity": "critical", "duration_seconds": 120, "recovery_seconds": 60}
	r := e.post("/api/v1/alert-rules", body)
	if r.Status != 201 || r.data()["is_enabled"] != true || r.data()["server_id"] != nil || !strings.HasPrefix(r.Header.Get("Location"), "/api/v1/alert-rules/") {
		t.Fatalf("criar: %d %s", r.Status, r.Raw)
	}
	id := r.data()["id"].(string)
	scoped := map[string]any{"name": "Disco /data", "metric_name": "disk_used_percent", "operator": ">", "threshold": 85, "severity": "warning", "server_id": srv}
	if r := e.post("/api/v1/alert-rules", scoped); r.Status != 201 || r.data()["server_id"] != srv {
		t.Fatalf("regra por servidor: %d %s", r.Status, r.Raw)
	}
	e.post("/api/v1/alert-rules", map[string]any{"name": "Sem comunicação", "metric_name": "server_offline", "operator": ">", "threshold": 120, "severity": "critical", "is_enabled": false})
	e.post("/api/v1/alert-rules", map[string]any{"name": "Serviço fora", "metric_name": "service_down", "operator": "==", "threshold": 1, "severity": "critical"})

	bad := map[string]map[string]any{
		"threshold ausente":  {"name": "x", "metric_name": "cpu_usage_percent", "operator": ">", "severity": "info"},
		"cpu > 100":          {"name": "x", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 150, "severity": "info"},
		"métrica":            {"name": "x", "metric_name": "uptime", "operator": ">", "threshold": 1, "severity": "info"},
		"operador":           {"name": "x", "metric_name": "cpu_usage_percent", "operator": "!=", "threshold": 1, "severity": "info"},
		"severidade":         {"name": "x", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 1, "severity": "grave"},
		"duração":            {"name": "x", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 1, "severity": "info", "duration_seconds": -5},
		"servidor inexist.":  {"name": "x", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 1, "severity": "info", "server_id": "00000000-0000-0000-0000-000000000000"},
		"service_down com >": {"name": "x", "metric_name": "service_down", "operator": ">", "threshold": 1, "severity": "info"},
	}
	for name, b := range bad {
		if r := e.post("/api/v1/alert-rules", b); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := e.post("/api/v1/alert-rules", `{"name":"x","metric_name":"cpu_usage_percent","operator":">","threshold":1,"severity":"info","query":"drop table"}`); r.Status != 400 {
		t.Errorf("campo desconhecido: %d", r.Status)
	}

	for q, want := range map[string]int{"": 4, "metric_name=cpu_usage_percent": 1, "severity=critical": 3, "enabled=false": 1, "enabled=true": 3, "server_id=" + srv: 1, "per_page=2&page=2": 2} {
		if r := e.admin("GET", "/api/v1/alert-rules?"+q, nil); r.Status != 200 || len(r.list()) != want {
			t.Errorf("%q: %d (esperado %d) %s", q, len(r.list()), want, r.Raw)
		}
	}
	if r := e.admin("GET", "/api/v1/alert-rules?enabled=talvez", nil); r.Status != 422 {
		t.Errorf("enabled inválido: %d", r.Status)
	}

	// atualização
	r = e.admin("PATCH", "/api/v1/alert-rules/"+id, map[string]any{"threshold": 80, "severity": "warning", "is_enabled": false})
	if r.Status != 200 || r.data()["threshold"] != float64(80) || r.data()["severity"] != "warning" || r.data()["is_enabled"] != false || r.data()["duration_seconds"] != float64(120) {
		t.Errorf("patch: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("PATCH", "/api/v1/alert-rules/"+id, map[string]any{"metric_name": "service_down"}); r.Status != 422 {
		t.Errorf("trocar a métrica invalida o conjunto: %d", r.Status)
	}
	if r := e.admin("PATCH", "/api/v1/alert-rules/"+id, `{}`); r.Status != 422 {
		t.Errorf("patch vazio: %d", r.Status)
	}
	if r := e.admin("PATCH", "/api/v1/alert-rules/00000000-0000-0000-0000-000000000000", map[string]any{"threshold": 1}); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/alert-rules/"+id, nil); r.Status != 200 || r.data()["threshold"] != float64(80) {
		t.Errorf("get: %s", r.Raw)
	}
	if r := e.admin("DELETE", "/api/v1/alert-rules/"+id, nil); r.Status != 204 {
		t.Errorf("delete: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/alert-rules/"+id, nil); r.Status != 404 {
		t.Errorf("após delete: %d", r.Status)
	}
	if r := e.admin("DELETE", "/api/v1/alert-rules/"+id, nil); r.Status != 404 {
		t.Errorf("delete repetido: %d", r.Status)
	}
	if e.count(`SELECT count(*) FROM alert_rules WHERE id=$1 AND deleted_at IS NOT NULL`, id) != 1 {
		t.Error("exclusão deve ser lógica")
	}
	for _, a := range []string{"alert_rule.create", "alert_rule.update", "alert_rule.delete"} {
		if e.count(`SELECT count(*) FROM audit_logs WHERE action=$1`, a) == 0 {
			t.Errorf("auditoria %s ausente", a)
		}
	}
}

func TestAlertsAndIncidentsAPIEndToEnd(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	now := time.Now().UTC()
	e.sample(srv, now, 97, 4, 500, 1000, nil, nil)
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id=$1`, srv)

	r := e.post("/api/v1/alert-rules", map[string]any{"name": "CPU alta", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 90, "severity": "critical", "duration_seconds": 0})
	ruleID := r.data()["id"].(string)
	// com duração, a regra cria apenas "pending": invisível na API e fora dos agregados do dashboard
	e.post("/api/v1/alert-rules", map[string]any{"name": "Mem lenta", "metric_name": "memory_used_percent", "operator": ">=", "threshold": 10, "severity": "warning", "duration_seconds": 600})

	if err := e.evaluator().Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM alerts WHERE status='pending'`) != 1 {
		t.Fatal("setup: deveria haver 1 pending")
	}
	l := e.admin("GET", "/api/v1/alerts", nil)
	if l.Status != 200 || len(l.list()) != 1 || l.meta()["total"] != float64(1) {
		t.Fatalf("lista: %s", l.Raw)
	}
	al := l.list()[0].(map[string]any)
	id := al["id"].(string)
	if al["status"] != "firing" || al["severity"] != "critical" || al["server_name"] != "web-1" || al["rule_name"] != "CPU alta" || al["incident_id"] == nil ||
		!strings.Contains(al["message"].(string), "97.0%") || al["rule_id"] != ruleID {
		t.Errorf("alerta: %v", al)
	}
	if d := e.admin("GET", "/api/v1/dashboard/summary", nil); fnum(d.data(), "alerts", "active") != float64(1) {
		t.Errorf("dashboard deve ignorar pending: %s", d.Raw)
	}
	pendingID := e.queryID(`SELECT id::text FROM alerts WHERE status='pending'`)
	if r := e.admin("GET", "/api/v1/alerts/"+pendingID, nil); r.Status != 404 {
		t.Errorf("pending não é um alerta: %d", r.Status)
	}
	if r := e.post("/api/v1/alerts/"+pendingID+"/acknowledge", nil); r.Status != 404 {
		t.Errorf("reconhecer pending: %d", r.Status)
	}

	// filtros
	for q, want := range map[string]int{"status=active": 1, "status=resolved": 0, "status=firing": 1, "severity=critical": 1, "severity=info": 0,
		"server_id=" + srv: 1, "rule_id=" + ruleID: 1, "from=" + ts(now.Add(-time.Hour)) + "&to=" + ts(now.Add(time.Hour)): 1, "from=" + ts(now.Add(time.Hour)): 0} {
		if r := e.admin("GET", "/api/v1/alerts?"+q, nil); r.Status != 200 || len(r.list()) != want {
			t.Errorf("%q: %d (esperado %d)", q, len(r.list()), want)
		}
	}
	for _, q := range []string{"status=x", "severity=x", "server_id=x", "status=pending", "from=ontem", "page=0", "from=" + ts(now) + "&to=" + ts(now.Add(-time.Hour))} {
		if r := e.admin("GET", "/api/v1/alerts?"+q, nil); r.Status != 422 {
			t.Errorf("%q deveria ser 422: %d", q, r.Status)
		}
	}
	if r := e.admin("GET", "/api/v1/alerts/"+id, nil); r.Status != 200 || r.data()["id"] != id {
		t.Errorf("get: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/alerts/00000000-0000-0000-0000-000000000000", nil); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}

	// reconhecimento
	r = e.post("/api/v1/alerts/"+id+"/acknowledge", map[string]any{"note": "olhando agora"})
	if r.Status != 200 || r.data()["status"] != "acknowledged" || r.data()["acknowledged_at"] == nil {
		t.Fatalf("ack: %d %s", r.Status, r.Raw)
	}
	if r := e.post("/api/v1/alerts/"+id+"/acknowledge", nil); r.Status != 200 {
		t.Errorf("ack repetido (idempotente): %d", r.Status)
	}
	if r := e.post("/api/v1/alerts/"+id+"/acknowledge", map[string]any{"note": strings.Repeat("x", 501)}); r.Status != 422 {
		t.Errorf("nota longa: %d", r.Status)
	}

	// incidentes
	incID := al["incident_id"].(string)
	ir := e.admin("GET", "/api/v1/incidents", nil)
	if ir.Status != 200 || len(ir.list()) != 1 {
		t.Fatalf("incidentes: %s", ir.Raw)
	}
	inc := ir.list()[0].(map[string]any)
	if inc["id"] != incID || inc["status"] != "open" || inc["server_name"] != "web-1" || inc["rule_name"] != "CPU alta" || inc["resolved_at"] != nil {
		t.Errorf("incidente: %v", inc)
	}
	det := e.admin("GET", "/api/v1/incidents/"+incID, nil)
	if det.Status != 200 || len(det.data()["alerts"].([]any)) != 1 {
		t.Errorf("detalhe: %s", det.Raw)
	}
	ev := e.admin("GET", "/api/v1/incidents/"+incID+"/events", nil)
	var types []string
	for _, x := range ev.list() {
		types = append(types, x.(map[string]any)["event_type"].(string))
	}
	if strings.Join(types, ",") != "opened,alert_triggered,acknowledged" {
		t.Errorf("eventos: %v", types)
	}
	if r := e.admin("GET", "/api/v1/servers/"+srv+"/incidents?status=open", nil); r.Status != 200 || len(r.list()) != 1 {
		t.Errorf("incidentes do servidor: %s", r.Raw)
	}
	for _, q := range []string{"status=x", "severity=x", "server_id=x", "to=x"} {
		if r := e.admin("GET", "/api/v1/incidents?"+q, nil); r.Status != 422 {
			t.Errorf("incidents %q: %d", q, r.Status)
		}
	}
	for _, p := range []string{"/api/v1/incidents/00000000-0000-0000-0000-000000000000", "/api/v1/incidents/00000000-0000-0000-0000-000000000000/events", "/api/v1/servers/00000000-0000-0000-0000-000000000000/incidents"} {
		if r := e.admin("GET", p, nil); r.Status != 404 {
			t.Errorf("%s: %d", p, r.Status)
		}
	}
	if r := e.admin("GET", "/api/v1/incidents/xyz", nil); r.Status != 400 {
		t.Errorf("id inválido: %d", r.Status)
	}

	// resolução manual fecha alerta e incidente
	r = e.post("/api/v1/alerts/"+id+"/resolve", nil)
	if r.Status != 200 || r.data()["status"] != "resolved" || r.data()["resolved_reason"] != "manual" {
		t.Fatalf("resolve: %d %s", r.Status, r.Raw)
	}
	if r := e.post("/api/v1/alerts/"+id+"/resolve", nil); r.Status != 409 || r.errCode() != "INVALID_STATE" {
		t.Errorf("resolver de novo: %d %s", r.Status, r.Raw)
	}
	if r := e.post("/api/v1/alerts/"+id+"/acknowledge", nil); r.Status != 409 {
		t.Errorf("reconhecer resolvido: %d", r.Status)
	}
	if d := e.admin("GET", "/api/v1/incidents/"+incID, nil); d.data()["status"] != "resolved" || d.data()["resolved_at"] == nil {
		t.Errorf("incidente deveria estar resolvido: %s", d.Raw)
	}
	for _, a := range []string{"alert.acknowledge", "alert.resolve"} {
		if e.count(`SELECT count(*) FROM audit_logs WHERE action=$1`, a) != 1 {
			t.Errorf("auditoria %s", a)
		}
	}
}

func TestNotificationChannelsAPI(t *testing.T) {
	e := newEnvCfg(t, withSecrets)
	body := map[string]any{"name": "Plantão", "bot_token": botToken, "chat_id": chatID, "min_severity": "warning"}
	r := e.post("/api/v1/notification-channels", body)
	if r.Status != 201 || strings.Contains(r.Raw, "AAH-") || strings.Contains(r.Raw, "bot_token") || r.data()["has_token"] != true ||
		r.data()["chat_id"] != chatID || r.data()["min_severity"] != "warning" || r.data()["channel_type"] != "telegram" {
		t.Fatalf("criar: %d %s", r.Status, r.Raw)
	}
	id := r.data()["id"].(string)
	if g := e.admin("GET", "/api/v1/notification-channels/"+id, nil); g.Status != 200 || strings.Contains(g.Raw, "AAH-") {
		t.Errorf("get: %s", g.Raw)
	}
	if l := e.admin("GET", "/api/v1/notification-channels", nil); l.Status != 200 || len(l.list()) != 1 || strings.Contains(l.Raw, "AAH-") {
		t.Errorf("list: %s", l.Raw)
	}
	var enc []byte
	e.pool.QueryRow(context.Background(), `SELECT secret_encrypted FROM notification_channels`).Scan(&enc)
	if len(enc) == 0 || bytes.Contains(enc, []byte("AAH-testtoken")) {
		t.Error("token deve estar cifrado no banco")
	}
	if e.count(`SELECT count(*) FROM audit_logs WHERE metadata::text LIKE '%AAH-%' OR metadata::text LIKE '%123456789%'`) != 0 {
		t.Error("token vazou para a auditoria")
	}

	bad := map[string]map[string]any{
		"chat não autorizado": {"name": "x", "bot_token": botToken, "chat_id": "777", "min_severity": "critical"},
		"token inválido":      {"name": "x", "bot_token": "abc", "chat_id": chatID},
		"chat inválido":       {"name": "x", "bot_token": botToken, "chat_id": "um chat"},
		"severidade":          {"name": "x", "bot_token": botToken, "chat_id": chatID, "min_severity": "fatal"},
		"tipo":                {"name": "x", "channel_type": "slack", "bot_token": botToken, "chat_id": chatID},
	}
	for name, b := range bad {
		if r := e.post("/api/v1/notification-channels", b); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := e.post("/api/v1/notification-channels", `{"name":"x","bot_token":"`+botToken+`","chat_id":"`+chatID+`","url":"http://x"}`); r.Status != 400 {
		t.Errorf("campo desconhecido: %d", r.Status)
	}

	r = e.admin("PATCH", "/api/v1/notification-channels/"+id, map[string]any{"min_severity": "critical", "is_enabled": false})
	if r.Status != 200 || r.data()["min_severity"] != "critical" || r.data()["is_enabled"] != false {
		t.Errorf("patch: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("PATCH", "/api/v1/notification-channels/"+id, map[string]any{"chat_id": "888"}); r.Status != 422 {
		t.Errorf("patch para chat não autorizado: %d", r.Status)
	}
	if r := e.admin("PATCH", "/api/v1/notification-channels/"+id, `{}`); r.Status != 422 {
		t.Errorf("patch vazio: %d", r.Status)
	}
	if r := e.post("/api/v1/notification-channels/"+id+"/test", nil); r.Status != 202 || r.data()["queued"] != true {
		t.Errorf("teste: %d %s", r.Status, r.Raw)
	}
	if e.count(`SELECT count(*) FROM notification_outbox WHERE channel_id=$1`, id) != 1 {
		t.Error("o teste deveria enfileirar uma mensagem")
	}
	if r := e.post("/api/v1/notification-channels/00000000-0000-0000-0000-000000000000/test", nil); r.Status != 404 {
		t.Errorf("teste de canal inexistente: %d", r.Status)
	}
	if r := e.admin("DELETE", "/api/v1/notification-channels/"+id, nil); r.Status != 204 {
		t.Errorf("delete: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/notification-channels/"+id, nil); r.Status != 404 {
		t.Errorf("após delete: %d", r.Status)
	}
	if e.count(`SELECT count(*) FROM notification_outbox`) != 0 {
		t.Error("mensagens pendentes de um canal removido devem sair da fila")
	}

	checkChannelsWithoutSecretsOrDestinations(t)
}

// Sem SECRETS_KEY não há como guardar o token com segurança; sem destinos autorizados nada é aceito.
func checkChannelsWithoutSecretsOrDestinations(t *testing.T) {
	t.Helper()
	ne := newEnvCfg(t, func(c *config.Config) { c.TelegramAllowedChatIDs = []string{chatID} }) // permitido, mas sem chave
	r := ne.post("/api/v1/notification-channels", map[string]any{"name": "x", "bot_token": botToken, "chat_id": chatID})
	if r.Status != 503 || r.errCode() != "SECRETS_NOT_CONFIGURED" {
		t.Errorf("sem SECRETS_KEY: %d %s", r.Status, r.Raw)
	}
	// e sem nenhum destino autorizado nada é aceito (seguro por padrão)
	r = newEnvCfg(t, func(c *config.Config) { c.SecretsKey = bytes.Repeat([]byte{9}, 32) }).post("/api/v1/notification-channels",
		map[string]any{"name": "x", "bot_token": botToken, "chat_id": chatID})
	if r.Status != 422 {
		t.Errorf("sem destinos autorizados: %d %s", r.Status, r.Raw)
	}
}
