//go:build integration

package http_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinela/internal/alerts"
	"sentinela/internal/config"
	"sentinela/internal/services"
	"sentinela/internal/ssrf"
)

const chatID = "-1001"
const botToken = "123456789:AAH-testtoken_abcdefghijklmnopqrstuvwxyz1234"

func allowLoopback(c *config.Config) {
	c.ServiceCheckAllowed, _ = ssrf.ParseAllowed("127.0.0.0/8")
}

func withSecrets(c *config.Config) {
	c.SecretsKey = bytes.Repeat([]byte{9}, 32)
	c.TelegramAllowedChatIDs = []string{chatID}
}

func (e *env) post(path string, body any) resp { return e.admin("POST", path, body) }

func (e *env) evaluator() *alerts.Evaluator {
	return &alerts.Evaluator{Pool: e.pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatTimeout: 60 * time.Second}
}

func (e *env) service(server, name, typ, target string) string {
	e.t.Helper()
	r := e.post("/api/v1/services", map[string]any{"server_id": server, "name": name, "service_type": typ, "target": target})
	if r.Status != 201 {
		e.t.Fatalf("criar serviço %s: %d %s", name, r.Status, r.Raw)
	}
	return r.data()["id"].(string)
}

func TestPhase4EndpointsRequireAdminKey(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	_, tok := e.issue(id, nil)
	zero := "00000000-0000-0000-0000-000000000000"
	reqs := [][2]string{
		{"GET", "/services"}, {"POST", "/services"}, {"GET", "/services/" + zero}, {"PATCH", "/services/" + zero},
		{"DELETE", "/services/" + zero}, {"POST", "/services/" + zero + "/check"}, {"GET", "/servers/" + id + "/services"},
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

func TestServicesCRUDAndValidation(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")

	r := e.post("/api/v1/services", map[string]any{"server_id": srv, "name": " api ", "service_type": "http", "target": "https://example.com/health"})
	if r.Status != 201 || r.data()["name"] != "api" || r.data()["status"] != "unknown" || !strings.HasPrefix(r.Header.Get("Location"), "/api/v1/services/") {
		t.Fatalf("criar: %d %s", r.Status, r.Raw)
	}
	cfg := r.data()["config"].(map[string]any)
	if cfg["timeout_seconds"] != float64(10) || cfg["interval_seconds"] != float64(60) || cfg["method"] != "GET" {
		t.Errorf("padrões: %v", cfg)
	}
	id := r.data()["id"].(string)
	if r := e.post("/api/v1/services", map[string]any{"server_id": srv, "name": "API", "service_type": "http", "target": "https://example.com"}); r.Status != 409 {
		t.Errorf("nome duplicado (sem diferenciar maiúsculas): %d", r.Status)
	}

	bad := []struct {
		name string
		body map[string]any
		want string
	}{
		{"SSRF metadata", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "http://169.254.169.254/latest/meta-data/"}, "target"},
		{"SSRF loopback", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "http://127.0.0.1:8080"}, "target"},
		{"SSRF rede privada", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "http://10.0.0.5/admin"}, "target"},
		{"SSRF localhost", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "http://localhost/"}, "target"},
		{"esquema file", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "file:///etc/passwd"}, "target"},
		{"credenciais na URL", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "http://u:p@example.com"}, "target"},
		{"tcp externo", map[string]any{"server_id": srv, "name": "a", "service_type": "tcp", "target": "8.8.8.8:53"}, "target"},
		{"systemd injeção", map[string]any{"server_id": srv, "name": "a", "service_type": "systemd", "target": "nginx; rm -rf /"}, "target"},
		{"tipo inválido", map[string]any{"server_id": srv, "name": "a", "service_type": "ssh", "target": "x"}, "service_type"},
		{"servidor inexistente", map[string]any{"server_id": "00000000-0000-0000-0000-000000000000", "name": "a", "service_type": "http", "target": "https://example.com"}, "server_id"},
		{"server_id inválido", map[string]any{"server_id": "x", "name": "a", "service_type": "http", "target": "https://example.com"}, "server_id"},
		{"timeout >= intervalo", map[string]any{"server_id": srv, "name": "a", "service_type": "http", "target": "https://example.com", "config": map[string]any{"timeout_seconds": 20, "interval_seconds": 15}}, "config.timeout_seconds"},
	}
	for _, c := range bad {
		r := e.post("/api/v1/services", c.body)
		if r.Status != 422 || !strings.Contains(r.Raw, `"`+c.want+`"`) {
			t.Errorf("%s: %d %s", c.name, r.Status, r.Raw)
		}
	}
	if r := e.post("/api/v1/services", `{"server_id":"`+srv+`","name":"x","service_type":"http","target":"https://example.com","command":"id"}`); r.Status != 400 {
		t.Errorf("campo desconhecido: %d", r.Status)
	}

	e.service(srv, "pg", "tcp", "127.0.0.1:5432")
	e.service(srv, "nginx", "systemd", "nginx")
	srv2 := e.createServer("db-1")
	e.service(srv2, "outro", "systemd", "cron")

	// listagem e filtros
	if r := e.admin("GET", "/api/v1/services", nil); r.Status != 200 || r.meta()["total"] != float64(4) {
		t.Errorf("lista: %s", r.Raw)
	}
	for q, want := range map[string]int{"server_id=" + srv: 3, "service_type=systemd": 2, "service_type=tcp": 1, "status=unknown": 4, "status=up": 0, "q=NGI": 1, "q=%25": 0, "per_page=2": 2} {
		if r := e.admin("GET", "/api/v1/services?"+q, nil); r.Status != 200 || len(r.list()) != want {
			t.Errorf("%s: %d itens (esperado %d) %s", q, len(r.list()), want, r.Raw)
		}
	}
	for _, q := range []string{"status=x", "service_type=x", "server_id=x", "per_page=0"} {
		if r := e.admin("GET", "/api/v1/services?"+q, nil); r.Status != 422 {
			t.Errorf("%s: %d", q, r.Status)
		}
	}
	if r := e.admin("GET", "/api/v1/servers/"+srv+"/services", nil); r.Status != 200 || len(r.list()) != 3 {
		t.Errorf("por servidor: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/servers/00000000-0000-0000-0000-000000000000/services", nil); r.Status != 404 {
		t.Errorf("servidor inexistente: %d", r.Status)
	}

	// atualização
	r = e.admin("PATCH", "/api/v1/services/"+id, map[string]any{"name": "api-v2", "config": map[string]any{"expected_status": []int{200, 204}, "interval_seconds": 30, "timeout_seconds": 5}})
	if r.Status != 200 || r.data()["name"] != "api-v2" || fnum(r.data(), "config", "interval_seconds") != float64(30) {
		t.Errorf("patch: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("PATCH", "/api/v1/services/"+id, map[string]any{"target": "http://10.1.1.1"}); r.Status != 422 {
		t.Errorf("patch com alvo interno: %d", r.Status)
	}
	if r := e.admin("PATCH", "/api/v1/services/"+id, `{}`); r.Status != 422 {
		t.Errorf("patch vazio: %d", r.Status)
	}
	pg := e.queryID(`SELECT id::text FROM monitored_services WHERE name='pg'`)
	if r := e.admin("PATCH", "/api/v1/services/"+pg, map[string]any{"name": "NGINX"}); r.Status != 409 {
		t.Errorf("renomear para nome existente: %d", r.Status)
	}
	if r := e.admin("PATCH", "/api/v1/services/"+pg, map[string]any{"config": map[string]any{"method": "GET"}}); r.Status != 422 {
		t.Errorf("config http em serviço tcp: %d", r.Status)
	}

	// exclusão lógica; o nome volta a ficar livre
	if r := e.admin("DELETE", "/api/v1/services/"+id, nil); r.Status != 204 {
		t.Fatalf("delete: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/services/"+id, nil); r.Status != 404 {
		t.Errorf("após delete: %d", r.Status)
	}
	if r := e.admin("DELETE", "/api/v1/services/"+id, nil); r.Status != 404 {
		t.Errorf("delete repetido: %d", r.Status)
	}
	e.service(srv, "api-v2", "http", "https://example.com")
	if r := e.admin("GET", "/api/v1/services/nao-uuid", nil); r.Status != 400 {
		t.Errorf("id inválido: %d", r.Status)
	}
	for _, a := range []string{"service.create", "service.update", "service.delete"} {
		if e.count(`SELECT count(*) FROM audit_logs WHERE action=$1`, a) == 0 {
			t.Errorf("auditoria %s ausente", a)
		}
	}
}

func TestServiceCheckEndpointCriteriaAndSSRF(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"app":"ok","db":"up"}`))
		case "/degraded-app":
			w.Write([]byte(`{"app":"ok","db":"down"}`))
		default:
			w.WriteHeader(503)
		}
	}))
	defer backend.Close()

	e := newEnvCfg(t, allowLoopback) // CIDR de loopback autorizado só para testar contra o httptest
	srv := e.createServer("web-1")
	mk := func(name, path string, cfg map[string]any) string {
		r := e.post("/api/v1/services", map[string]any{"server_id": srv, "name": name, "service_type": "http", "target": backend.URL + path, "config": cfg})
		if r.Status != 201 {
			t.Fatalf("%s: %d %s", name, r.Status, r.Raw)
		}
		return r.data()["id"].(string)
	}
	check := func(id string) resp { return e.post("/api/v1/services/"+id+"/check", nil) }

	ok := mk("ok", "/ok", map[string]any{"body_contains": `"db":"up"`})
	r := check(ok)
	if r.Status != 200 || fnum(r.data(), "result", "status") != "up" || fnum(r.data(), "service", "status") != "up" ||
		fnum(r.data(), "result", "latency_ms") == nil || fnum(r.data(), "service", "last_checked_at") == nil || fnum(r.data(), "result", "status_code") != float64(200) {
		t.Fatalf("up: %d %s", r.Status, r.Raw)
	}

	// 200 OK mas aplicação não saudável: o critério de corpo detecta
	deg := mk("degradada", "/degraded-app", map[string]any{"body_contains": `"db":"up"`})
	r = check(deg)
	if fnum(r.data(), "result", "status") != "down" || !strings.Contains(r.Raw, "corpo") {
		t.Errorf("critério de corpo: %s", r.Raw)
	}

	bad := mk("fora", "/outro", nil)
	r = check(bad)
	if fnum(r.data(), "result", "status") != "down" || fnum(r.data(), "result", "status_code") != float64(503) || fnum(r.data(), "service", "consecutive_failures") != float64(1) {
		t.Errorf("down: %s", r.Raw)
	}
	r = check(bad)
	if fnum(r.data(), "service", "consecutive_failures") != float64(2) {
		t.Errorf("falhas consecutivas: %s", r.Raw)
	}
	// ajustar o critério para aceitar 503 recupera e zera as falhas
	e.admin("PATCH", "/api/v1/services/"+bad, map[string]any{"config": map[string]any{"expected_status": []int{503}}})
	r = check(bad)
	if fnum(r.data(), "result", "status") != "up" || fnum(r.data(), "service", "consecutive_failures") != float64(0) || fnum(r.data(), "service", "status_changed_at") == nil {
		t.Errorf("recuperação: %s", r.Raw)
	}

	// serviços tcp/systemd são do agente: a API não os verifica
	tcp := e.service(srv, "pg", "tcp", "127.0.0.1:5432")
	if r := check(tcp); r.Status != 409 || r.errCode() != "CHECK_NOT_CENTRAL" {
		t.Errorf("tcp central: %d %s", r.Status, r.Raw)
	}
	if r := e.post("/api/v1/services/00000000-0000-0000-0000-000000000000/check", nil); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}

	// Ambiente com a POLÍTICA PADRÃO (sem CIDR autorizado): um alvo interno que tenha entrado no
	// banco por outro caminho continua sendo bloqueado e o servidor interno nunca é contatado.
	strict := newEnv(t, adminKey)
	ssrv := strict.createServer("web-1")
	var poisoned string
	strict.pool.QueryRow(context.Background(), `INSERT INTO monitored_services (server_id, name, service_type, target, config)
		VALUES ($1,'envenenado','http',$2,'{"timeout_seconds":3,"interval_seconds":60}') RETURNING id`, ssrv, backend.URL+"/ok").Scan(&poisoned)
	before := hits.Load()
	r = strict.post("/api/v1/services/"+poisoned+"/check", nil)
	if r.Status != 200 || fnum(r.data(), "result", "status") != "down" || !strings.Contains(r.Raw, "política") {
		t.Errorf("alvo interno deveria ser bloqueado: %s", r.Raw)
	}
	if hits.Load() != before {
		t.Errorf("SSRF: o servidor interno recebeu %d requisições", hits.Load()-before)
	}
	if msg, _ := fnum(r.data(), "result", "error").(string); strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "dial") {
		t.Errorf("o erro não deve expor detalhes de rede interna: %s", msg)
	}
}

func TestRunnerClaimsDueServicesExactlyOnceAcrossInstances(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	e := newEnvCfg(t)
	srv := e.createServer("web-1")
	for i := 0; i < 6; i++ {
		e.exec(`INSERT INTO monitored_services (server_id, name, service_type, target, config) VALUES ($1,$2,'http',$3,'{"timeout_seconds":3,"interval_seconds":60}')`,
			srv, fmt.Sprintf("svc-%d", i), fmt.Sprintf("%s/%d", backend.URL, i))
	}
	// serviço de agente e serviço removido não são verificados pelo executor central
	e.exec(`INSERT INTO monitored_services (server_id, name, service_type, target) VALUES ($1,'tcp','tcp','127.0.0.1:1')`, srv)
	e.exec(`INSERT INTO monitored_services (server_id, name, service_type, target, deleted_at) VALUES ($1,'removido','http','https://example.com', now())`, srv)

	pre, _ := ssrf.ParseAllowed("127.0.0.0/8")
	newRunner := func() *services.Runner {
		return &services.Runner{Repo: services.NewRepository(e.pool), Checker: services.NewChecker(ssrf.Policy{Allowed: pre}),
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Batch: 3}
	}
	var wg sync.WaitGroup
	var total atomic.Int32
	for i := 0; i < 4; i++ { // quatro "instâncias" em paralelo, lotes de 3
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := newRunner()
			for j := 0; j < 3; j++ {
				n, err := r.RunDue(context.Background())
				if err != nil {
					t.Error(err)
				}
				total.Add(int32(n))
			}
		}()
	}
	wg.Wait()
	if total.Load() != 6 || hits.Load() != 6 {
		t.Errorf("cada serviço deve ser verificado exatamente uma vez: execuções=%d requisições=%d", total.Load(), hits.Load())
	}
	if e.count(`SELECT count(*) FROM monitored_services WHERE service_type='http' AND status='up' AND deleted_at IS NULL`) != 6 {
		t.Error("todos deveriam estar up")
	}
	if e.count(`SELECT count(*) FROM monitored_services WHERE next_check_at <= now() AND service_type='http' AND deleted_at IS NULL`) != 0 {
		t.Error("a próxima verificação deveria estar agendada para o futuro")
	}
	if n, _ := newRunner().RunDue(context.Background()); n != 0 {
		t.Errorf("nada vencido: %d", n)
	}
	// alterar o serviço o reagenda para verificação imediata
	id := e.queryID(`SELECT id::text FROM monitored_services WHERE name='svc-0'`)
	e.admin("PATCH", "/api/v1/services/"+id, map[string]any{"name": "svc-0b"})
	if n, _ := newRunner().RunDue(context.Background()); n != 1 {
		t.Errorf("serviço alterado deveria ser reverificado: %d", n)
	}
	// servidor desativado: seus serviços deixam de ser verificados
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "disabled"})
	e.exec(`UPDATE monitored_services SET next_check_at = now()`)
	if n, _ := newRunner().RunDue(context.Background()); n != 0 {
		t.Errorf("servidor desativado: %d", n)
	}
}

func TestAgentServicesFlow(t *testing.T) {
	e := newEnv(t, adminKey)
	a, b := e.createServer("srv-a"), e.createServer("srv-b")
	_, tok := e.issue(a, nil)
	pg := e.service(a, "pg", "tcp", "127.0.0.1:5432")
	nginx := e.service(a, "nginx", "systemd", "nginx")
	httpSvc := e.service(a, "site", "http", "https://example.com")
	other := e.service(b, "cron", "systemd", "cron")

	// /agent/config entrega só os serviços locais do PRÓPRIO servidor, sem comandos
	r := e.do("GET", "/api/v1/agent/config", tok, nil)
	list, _ := r.data()["services"].([]any)
	if r.Status != 200 || len(list) != 2 {
		t.Fatalf("config: %d %s", r.Status, r.Raw)
	}
	ids := map[string]bool{}
	for _, it := range list {
		m := it.(map[string]any)
		ids[m["id"].(string)] = true
		for k := range m {
			if k == "command" || k == "exec" || k == "script" || k == "config" {
				t.Errorf("config do agente não pode conter %q", k)
			}
		}
	}
	if !ids[pg] || !ids[nginx] || ids[httpSvc] || ids[other] {
		t.Errorf("serviços do agente: %v", ids)
	}

	now := time.Now().UTC()
	rep := func(checked time.Time, results ...map[string]any) map[string]any {
		rs := make([]any, len(results))
		for i, x := range results {
			rs[i] = x
		}
		return map[string]any{"checked_at": checked.Format(time.RFC3339Nano), "results": rs}
	}
	r = e.do("POST", "/api/v1/agent/services", tok, rep(now.Add(-time.Second),
		map[string]any{"service_id": pg, "status": "up", "latency_ms": 3},
		map[string]any{"service_id": nginx, "status": "down", "error": "unidade sem processos\x07\x1b[31m em execução"},
		map[string]any{"service_id": other, "status": "up"},    // serviço de OUTRO servidor
		map[string]any{"service_id": httpSvc, "status": "up"})) // serviço central
	if r.Status != 200 || r.data()["accepted"] != float64(2) || len(r.data()["rejected"].([]any)) != 2 {
		t.Fatalf("relatório: %d %s", r.Status, r.Raw)
	}
	for _, rj := range r.data()["rejected"].([]any) {
		if rj.(map[string]any)["reason"] != "unknown_service" {
			t.Errorf("motivo: %v", rj)
		}
	}
	s := e.admin("GET", "/api/v1/services/"+pg, nil).data()
	if s["status"] != "up" || s["last_latency_ms"] != float64(3) || s["last_checked_at"] == nil {
		t.Errorf("pg: %v", s)
	}
	s = e.admin("GET", "/api/v1/services/"+nginx, nil).data()
	if s["status"] != "down" || strings.ContainsAny(s["last_error"].(string), "\x07\x1b") {
		t.Errorf("nginx / erro deveria ser sanitizado: %q", s["last_error"])
	}
	if e.admin("GET", "/api/v1/services/"+other, nil).data()["status"] != "unknown" || e.admin("GET", "/api/v1/services/"+httpSvc, nil).data()["status"] != "unknown" {
		t.Error("o agente não pode alterar serviços de outro servidor nem centrais")
	}
	// resultado mais antigo que o gravado é recusado (stale)
	r = e.do("POST", "/api/v1/agent/services", tok, rep(now.Add(-30*time.Second), map[string]any{"service_id": pg, "status": "down"}))
	if rj := r.data()["rejected"].([]any); r.data()["accepted"] != float64(0) || len(rj) != 1 || rj[0].(map[string]any)["reason"] != "stale" {
		t.Errorf("stale: %s", r.Raw)
	}
	if e.admin("GET", "/api/v1/services/"+pg, nil).data()["status"] != "up" {
		t.Error("resultado antigo não pode sobrescrever o novo")
	}

	bad := map[string]map[string]any{
		"status inválido": rep(now, map[string]any{"service_id": pg, "status": "ok"}),
		"duplicado":       rep(now, map[string]any{"service_id": pg, "status": "up"}, map[string]any{"service_id": pg, "status": "up"}),
		"uuid inválido":   rep(now, map[string]any{"service_id": "x", "status": "up"}),
		"futuro":          rep(now.Add(time.Hour), map[string]any{"service_id": pg, "status": "up"}),
		"antigo":          rep(now.Add(-3*time.Hour), map[string]any{"service_id": pg, "status": "up"}),
		"vazio":           rep(now),
		"latência":        rep(now, map[string]any{"service_id": pg, "status": "up", "latency_ms": -1}),
	}
	for name, body := range bad {
		if r := e.do("POST", "/api/v1/agent/services", tok, body); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	many := make([]map[string]any, 101)
	for i := range many {
		many[i] = map[string]any{"service_id": fmt.Sprintf("%08d-0000-0000-0000-000000000000", i), "status": "up"}
	}
	if r := e.do("POST", "/api/v1/agent/services", tok, rep(now, many...)); r.Status != 422 {
		t.Errorf(">100 resultados: %d", r.Status)
	}
	if r := e.do("POST", "/api/v1/agent/services", tok, `{"checked_at":"`+now.Format(time.RFC3339)+`","server_id":"`+b+`","results":[]}`); r.Status != 400 {
		t.Errorf("server_id no corpo: %d", r.Status)
	}
	if r := e.do("POST", "/api/v1/agent/services", "", rep(now)); r.Status != 401 {
		t.Errorf("sem credencial: %d", r.Status)
	}
}

func TestAlertRulesAPI(t *testing.T) {
	e := newEnv(t, adminKey)
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
