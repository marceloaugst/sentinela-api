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
		{"GET", "/servers/" + id + "/incidents"}, {"GET", "/alert-rules"}, {"GET", "/alert-rules/" + zero},
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

// rule insere direto no banco uma regra de teste (a API não cadastra regras) e devolve o id.
func (e *env) rule(name, metric, op string, threshold float64, severity string, duration int, serverID string) string {
	e.t.Helper()
	var sid any
	if serverID != "" {
		sid = serverID
	}
	return e.queryID(`INSERT INTO alert_rules (name, metric_name, operator, threshold, severity, duration_seconds, server_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id::text`, name, metric, op, threshold, severity, duration, sid)
}

func TestAlertRulesAreAutomaticAndReadOnly(t *testing.T) {
	e := newEnv(t, adminKey)
	ctx := context.Background()
	legacy := e.rule("Regra antiga", "cpu_usage_percent", ">", 50, "info", 0, "")
	if err := alerts.SyncCatalog(ctx, e.pool); err != nil {
		t.Fatal(err)
	}
	if err := alerts.SyncCatalog(ctx, e.pool); err != nil { // idempotente
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM alert_rules WHERE deleted_at IS NULL`); n != len(alerts.Catalog) {
		t.Fatalf("regras ativas = %d, esperado %d (o catálogo)", n, len(alerts.Catalog))
	}
	if e.count(`SELECT count(*) FROM alert_rules WHERE id=$1 AND deleted_at IS NOT NULL AND NOT is_enabled`, legacy) != 1 {
		t.Error("a regra cadastrada à mão deve ser arquivada")
	}

	r := e.admin("GET", "/api/v1/alert-rules", nil)
	if r.Status != 200 || len(r.list()) != len(alerts.Catalog) {
		t.Fatalf("lista: %d %s", r.Status, r.Raw)
	}
	first := r.list()[0].(map[string]any)
	if first["priority"] != float64(1) || first["code"] == nil || first["server_id"] != nil {
		t.Errorf("a lista deve vir por prioridade, com código e sem escopo por servidor: %v", first)
	}
	for q, want := range map[string]int{"priority=1": 3, "priority=2": 6, "priority=3": 6, "priority=4": 0, "metric_name=disk_used_percent": 2, "severity=warning": 6} {
		if r := e.admin("GET", "/api/v1/alert-rules?"+q, nil); r.Status != 200 || len(r.list()) != want {
			t.Errorf("%q: %d (esperado %d) %s", q, len(r.list()), want, r.Raw)
		}
	}
	if r := e.admin("GET", "/api/v1/alert-rules?priority=9", nil); r.Status != 422 {
		t.Errorf("priority inválida: %d", r.Status)
	}
	id := first["id"].(string)
	if r := e.admin("GET", "/api/v1/alert-rules/"+id, nil); r.Status != 200 {
		t.Errorf("get: %d", r.Status)
	}
	// não há cadastro, edição nem exclusão
	for _, rq := range [][2]string{{"POST", "/api/v1/alert-rules"}, {"PATCH", "/api/v1/alert-rules/" + id}, {"DELETE", "/api/v1/alert-rules/" + id}} {
		if r := e.admin(rq[0], rq[1], map[string]any{"threshold": 1}); r.Status != 404 && r.Status != 405 {
			t.Errorf("%s %s deveria não existir: %d", rq[0], rq[1], r.Status)
		}
	}

	// um ajuste no banco é desfeito na próxima sincronização (o código é a fonte da verdade)
	e.exec(`UPDATE alert_rules SET threshold = 1, is_enabled = false WHERE id=$1`, id)
	if err := alerts.SyncCatalog(ctx, e.pool); err != nil {
		t.Fatal(err)
	}
	if r := e.admin("GET", "/api/v1/alert-rules/"+id, nil); r.data()["is_enabled"] != true || r.data()["threshold"] == float64(1) {
		t.Errorf("a sincronização deve restaurar a regra: %s", r.Raw)
	}
}

func TestAlertsAndIncidentsAPIEndToEnd(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	now := time.Now().UTC()
	e.sample(srv, now, 97, 4, 500, 1000, nil, nil)
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id=$1`, srv)

	ruleID := e.rule("CPU alta", "cpu_usage_percent", ">", 90, "critical", 0, "")
	// com duração, a regra cria apenas "pending": invisível na API e fora dos agregados do dashboard
	e.rule("Mem lenta", "memory_used_percent", ">=", 10, "warning", 600, "")

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
	r := e.post("/api/v1/alerts/"+id+"/acknowledge", map[string]any{"note": "olhando agora"})
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
