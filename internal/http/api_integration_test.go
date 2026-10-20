//go:build integration

package http_test

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/auth"
	"sentinela/internal/config"
	"sentinela/internal/events"
	apphttp "sentinela/internal/http"
	"sentinela/internal/metrics"
	"sentinela/internal/telemetry"
	"sentinela/internal/testutil"
)

const adminKey = "0123456789abcdef0123456789abcdef-admin"

type env struct {
	t       *testing.T
	pool    *pgxpool.Pool
	url     string // URL do banco do teste (schema isolado), para conexões dedicadas
	srv     *httptest.Server
	cfg     config.Config
	hub     *events.Hub
	auth    *auth.Service
	reg     *apphttp.Registry
	metrics *telemetry.Metrics
	log     *slog.Logger
}

// newEnv usa limites de taxa folgados para não interferir nos testes funcionais.
func newEnv(t *testing.T, key string) *env { return newEnvRate(t, key, 1000, 1000) }

// newEnvCfg permite ajustar a configuração (limites folgados de taxa).
func newEnvCfg(t *testing.T, mut ...func(*config.Config)) *env {
	return newEnvRate(t, adminKey, 1000, 1000, mut...)
}

// newEnvRate com rate/burst 0 usa os padrões de produção do agente.
func newEnvRate(t *testing.T, key string, rate, burst int, mut ...func(*config.Config)) *env {
	t.Helper()
	pool, url := testutil.NewDBURL(t)
	cfg := config.Config{
		MaxBodyBytes: 1 << 20, RequestTimeout: 10 * time.Second, AdminAPIKey: key,
		AgentHeartbeatTimeout: 60 * time.Second, AgentCollectInterval: 15 * time.Second,
		AgentRatePerSecond: rate, AgentRateBurst: burst,
		// Argon2id leve: os testes criam muitos usuários e fazem muitos logins (a política real é testada à parte)
		Argon2MemoryKiB: 256, Argon2Time: 1, Argon2Threads: 1,
		SessionAbsoluteTTL: 24 * time.Hour, SessionIdleTTL: 2 * time.Hour, CookieSameSite: "lax",
		LoginMaxFailures: 5, LoginLockWindow: 15 * time.Minute, APIRateLimit: 100000, APIRateBurst: 100000,
	}
	for _, m := range mut {
		m(&cfg)
	}
	e := &env{t: t, pool: pool, url: url, cfg: cfg, metrics: telemetry.NewMetrics(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), reg: &apphttp.Registry{}}
	e.auth = apphttp.NewAuthService(cfg, pool, e.log)
	e.hub = e.startHub()
	e.srv = httptest.NewServer(e.router(e.hub))
	t.Cleanup(e.srv.Close)
	return e
}

// startHub inicia um hub de eventos (equivale a uma instância da API) e o encerra ao fim do teste.
func (e *env) startHub() *events.Hub {
	h := events.NewHub(e.url, e.pool, e.log, e.metrics)
	if e.cfg.SSEMaxClients > 0 {
		h.MaxClients = e.cfg.SSEMaxClients
	}
	if e.cfg.SSEMaxClientsPerIP > 0 {
		h.MaxPerIP = e.cfg.SSEMaxClientsPerIP
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done; h.Close() })
	select {
	case <-h.Ready():
	case <-time.After(10 * time.Second):
		e.t.Fatal("hub de eventos não ficou pronto")
	}
	return h
}

func (e *env) router(h *events.Hub) nethttp.Handler {
	return apphttp.NewRouter(apphttp.Deps{
		Config: e.cfg, Log: e.log, Metrics: e.metrics, DB: e.pool, Pool: e.pool, Hub: h, Auth: e.auth, Registry: e.reg, Version: "test",
	})
}

type resp struct {
	Status int
	Header nethttp.Header
	Body   map[string]any
	Raw    string
}

func (r resp) data() map[string]any { d, _ := r.Body["data"].(map[string]any); return d }
func (r resp) list() []any          { d, _ := r.Body["data"].([]any); return d }
func (r resp) meta() map[string]any { d, _ := r.Body["meta"].(map[string]any); return d }
func (r resp) errCode() string {
	e, _ := r.Body["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func (e *env) do(method, path, bearer string, body any) resp {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		var b []byte
		if s, ok := body.(string); ok {
			b = []byte(s)
		} else {
			b, _ = json.Marshal(body)
		}
		rdr = bytes.NewReader(b)
	}
	req, _ := nethttp.NewRequest(method, e.srv.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, Raw: string(raw)}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func (e *env) admin(method, path string, body any) resp { return e.do(method, path, adminKey, body) }

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *env) createServer(name string) string {
	e.t.Helper()
	r := e.admin("POST", "/api/v1/servers", map[string]string{"name": name, "hostname": name + ".example.com"})
	if r.Status != 201 {
		e.t.Fatalf("criar servidor: %d %s", r.Status, r.Raw)
	}
	return r.data()["id"].(string)
}

// issue devolve (credentialID, token).
func (e *env) issue(serverID string, body any) (string, string) {
	e.t.Helper()
	r := e.admin("POST", "/api/v1/servers/"+serverID+"/agent-credentials", body)
	if r.Status != 201 {
		e.t.Fatalf("emitir credencial: %d %s", r.Status, r.Raw)
	}
	return r.data()["id"].(string), r.data()["token"].(string)
}

func payload(collected time.Time, mutate ...func(map[string]any)) map[string]any {
	p := map[string]any{
		"agent_version": "0.1.0",
		"collected_at":  collected.UTC().Format(time.RFC3339Nano),
		"host":          map[string]any{"hostname": "h", "os": "Ubuntu", "os_version": "24.04", "architecture": "amd64", "uptime_seconds": 1000},
		"cpu":           map[string]any{"usage_percent": 12.5, "count": 4, "load_average": map[string]any{"m1": 0.1, "m5": 0.2, "m15": 0.3}},
		"memory":        map[string]any{"total_bytes": 1000, "used_bytes": 400, "available_bytes": 600, "swap_total_bytes": 100, "swap_used_bytes": 10},
		"network":       map[string]any{"rx_bytes_total": 1000, "tx_bytes_total": 2000},
		"disks": []any{
			map[string]any{"mount_point": "/", "filesystem": "ext4", "total_bytes": 1000, "used_bytes": 250, "available_bytes": 750},
			map[string]any{"mount_point": "/data", "filesystem": "xfs", "total_bytes": 2000, "used_bytes": 500, "available_bytes": 1500},
		},
	}
	for _, m := range mutate {
		m(p)
	}
	return p
}

func TestAdminGuard(t *testing.T) {
	e := newEnv(t, adminKey)
	if r := e.do("GET", "/api/v1/servers", "", nil); r.Status != 401 || r.errCode() != "UNAUTHORIZED" {
		t.Errorf("sem chave: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/api/v1/servers", "chave-errada", nil); r.Status != 401 {
		t.Errorf("chave errada: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/servers", nil); r.Status != 200 {
		t.Errorf("chave correta: %d", r.Status)
	}
	// um token de agente NÃO dá acesso administrativo
	id := e.createServer("web-1")
	_, tok := e.issue(id, nil)
	if r := e.do("GET", "/api/v1/servers", tok, nil); r.Status != 401 {
		t.Errorf("token de agente em rota admin: %d", r.Status)
	}
	// e a chave administrativa não autentica como agente
	if r := e.do("GET", "/api/v1/agent/config", adminKey, nil); r.Status != 401 {
		t.Errorf("chave admin em rota de agente: %d", r.Status)
	}
}

// Sem ADMIN_API_KEY a chave de automação não existe: nenhum valor de Bearer (inclusive vazio) autentica.
func TestAPIKeyDisabledWhenNotConfigured(t *testing.T) {
	e := newEnv(t, "")
	for _, b := range []string{"", "x", "Bearer", strings.Repeat("a", 40)} {
		if r := e.do("GET", "/api/v1/servers", b, nil); r.Status != 401 || r.errCode() != "UNAUTHORIZED" {
			t.Errorf("sem ADMIN_API_KEY (%q): %d %s", b, r.Status, r.Raw)
		}
	}
}

func TestServersCRUD(t *testing.T) {
	e := newEnv(t, adminKey)

	r := e.admin("POST", "/api/v1/servers", map[string]string{"name": " web-1 ", "hostname": "web-1.example.com"})
	if r.Status != 201 || r.data()["name"] != "web-1" || r.data()["connection_status"] != "unknown" ||
		r.data()["status"] != "active" || !strings.HasPrefix(r.Header.Get("Location"), "/api/v1/servers/") {
		t.Fatalf("criar: %d %s", r.Status, r.Raw)
	}
	id := r.data()["id"].(string)

	if r := e.admin("POST", "/api/v1/servers", map[string]string{"name": "WEB-1", "hostname": "x"}); r.Status != 409 {
		t.Errorf("nome duplicado: %d", r.Status)
	}
	r = e.admin("POST", "/api/v1/servers", map[string]string{"name": "", "hostname": "http://x"})
	if r.Status != 422 || r.errCode() != "VALIDATION_ERROR" || len(r.Body["error"].(map[string]any)["details"].([]any)) != 2 {
		t.Errorf("validação: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("POST", "/api/v1/servers", `{"name":"a","hostname":"b","is_admin":true}`); r.Status != 400 {
		t.Errorf("campo desconhecido: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/servers/nao-e-uuid", nil); r.Status != 400 || r.errCode() != "INVALID_ID" {
		t.Errorf("id inválido: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/servers/00000000-0000-0000-0000-000000000000", nil); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/servers/"+id, nil); r.Status != 200 || r.data()["hostname"] != "web-1.example.com" {
		t.Errorf("get: %d %s", r.Status, r.Raw)
	}

	// PATCH
	if r := e.admin("PATCH", "/api/v1/servers/"+id, map[string]string{"status": "maintenance"}); r.Status != 200 || r.data()["status"] != "maintenance" {
		t.Errorf("patch status: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("PATCH", "/api/v1/servers/"+id, `{}`); r.Status != 422 {
		t.Errorf("patch vazio: %d", r.Status)
	}
	if r := e.admin("PATCH", "/api/v1/servers/"+id, map[string]string{"status": "online"}); r.Status != 422 {
		t.Errorf("status inválido: %d", r.Status)
	}
	id2 := e.createServer("db-1")
	if r := e.admin("PATCH", "/api/v1/servers/"+id2, map[string]string{"name": "web-1"}); r.Status != 409 {
		t.Errorf("rename conflitante: %d", r.Status)
	}

	// Listagem: busca, filtros, ordenação e paginação
	for i := 0; i < 3; i++ {
		e.createServer(fmt.Sprintf("app-%d", i))
	}
	r = e.admin("GET", "/api/v1/servers?per_page=2&page=2&sort=name&order=asc", nil)
	if r.Status != 200 || len(r.list()) != 2 || r.meta()["total"] != float64(5) || r.meta()["total_pages"] != float64(3) {
		t.Errorf("paginação: %d %s", r.Status, r.Raw)
	}
	if r := e.admin("GET", "/api/v1/servers?q=APP-", nil); len(r.list()) != 3 {
		t.Errorf("busca q: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/servers?q=%25", nil); len(r.list()) != 0 {
		t.Errorf("curinga %% deve ser literal: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/servers?status=maintenance", nil); len(r.list()) != 1 {
		t.Errorf("filtro status: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/servers?connection=unknown", nil); len(r.list()) != 5 {
		t.Errorf("filtro connection: %s", r.Raw)
	}
	r = e.admin("GET", "/api/v1/servers?sort=name&order=desc&per_page=1", nil)
	if r.list()[0].(map[string]any)["name"] != "web-1" {
		t.Errorf("ordenação desc: %s", r.Raw)
	}
	for _, q := range []string{"sort=password", "order=sideways", "page=0", "per_page=101", "status=x", "connection=x"} {
		if r := e.admin("GET", "/api/v1/servers?"+q, nil); r.Status != 422 {
			t.Errorf("%s deveria ser 422: %d", q, r.Status)
		}
	}

	// DELETE lógico
	if r := e.admin("DELETE", "/api/v1/servers/"+id, nil); r.Status != 204 {
		t.Errorf("delete: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/servers/"+id, nil); r.Status != 404 {
		t.Errorf("get após delete: %d", r.Status)
	}
	if r := e.admin("DELETE", "/api/v1/servers/"+id, nil); r.Status != 404 {
		t.Errorf("delete repetido: %d", r.Status)
	}
	if e.count(`SELECT count(*) FROM servers WHERE id=$1 AND deleted_at IS NOT NULL`, id) != 1 {
		t.Error("registro deveria permanecer com deleted_at")
	}
	e.createServer("web-1") // nome liberado após a exclusão

	// auditoria
	for action, min := range map[string]int{"server.create": 6, "server.update": 1, "server.delete": 1} {
		if n := e.count(`SELECT count(*) FROM audit_logs WHERE action=$1`, action); n < min {
			t.Errorf("auditoria %s: %d (< %d)", action, n, min)
		}
	}
}

func TestAgentCredentialsAndIngestion(t *testing.T) {
	e := newEnv(t, adminKey)
	srvA := e.createServer("srv-a")
	srvB := e.createServer("srv-b")

	// emissão: token exibido uma vez, só o hash vai ao banco
	r := e.admin("POST", "/api/v1/servers/"+srvA+"/agent-credentials", nil)
	if r.Status != 201 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("emitir: %d %s", r.Status, r.Raw)
	}
	token := r.data()["token"].(string)
	credID := r.data()["id"].(string)
	if !strings.HasPrefix(token, "snt_") {
		t.Fatalf("token: %q", token)
	}
	if e.count(`SELECT count(*) FROM agent_credentials WHERE token_hash = $1`, []byte(token)) != 0 {
		t.Error("token em texto puro não pode estar na coluna de hash")
	}
	if e.count(`SELECT count(*) FROM audit_logs WHERE metadata::text LIKE '%' || $1 || '%'`, token[4:]) != 0 {
		t.Error("token vazou para o audit_logs")
	}
	list := e.admin("GET", "/api/v1/servers/"+srvA+"/agent-credentials", nil)
	if list.Status != 200 || len(list.list()) != 1 || strings.Contains(list.Raw, token) || strings.Contains(list.Raw, "token") {
		t.Errorf("listagem não deve conter token: %s", list.Raw)
	}
	if e.admin("POST", "/api/v1/servers/00000000-0000-0000-0000-000000000000/agent-credentials", nil).Status != 404 {
		t.Error("emitir para servidor inexistente deveria ser 404")
	}

	// autenticação
	if r := e.do("POST", "/api/v1/agent/heartbeat", "", map[string]any{"agent_version": "1"}); r.Status != 401 {
		t.Errorf("sem credencial: %d", r.Status)
	}
	if r := e.do("POST", "/api/v1/agent/heartbeat", "snt_"+strings.Repeat("0", 64), map[string]any{"agent_version": "1"}); r.Status != 401 {
		t.Errorf("credencial desconhecida: %d", r.Status)
	}

	// heartbeat atualiza presença e inventário
	r = e.do("POST", "/api/v1/agent/heartbeat", token, map[string]any{
		"agent_version": "0.1.0", "host": map[string]any{"os": "Ubuntu", "os_version": "24.04", "architecture": "arm64"}})
	if r.Status != 200 {
		t.Fatalf("heartbeat: %d %s", r.Status, r.Raw)
	}
	s := e.admin("GET", "/api/v1/servers/"+srvA, nil).data()
	if s["connection_status"] != "online" || s["agent_version"] != "0.1.0" || s["architecture"] != "arm64" || s["last_seen_at"] == nil {
		t.Errorf("servidor após heartbeat: %v", s)
	}
	if e.admin("GET", "/api/v1/servers/"+srvB, nil).data()["last_seen_at"] != nil {
		t.Error("heartbeat de A não pode afetar B")
	}

	// config do agente
	if r := e.do("GET", "/api/v1/agent/config", token, nil); r.Status != 200 || r.data()["collect_interval_seconds"] != float64(15) {
		t.Errorf("config: %d %s", r.Status, r.Raw)
	} else {
		for k := range r.data() {
			if strings.Contains(k, "token") || strings.Contains(k, "command") || strings.Contains(k, "secret") {
				t.Errorf("config não deve conter %q", k)
			}
		}
	}

	// métricas
	now := time.Now().UTC().Truncate(time.Millisecond)
	ts := now.Add(-5 * time.Second)
	r = e.do("POST", "/api/v1/agent/metrics", token, payload(ts))
	if r.Status != 200 || r.data()["stored"] != true || r.data()["duplicate"] != false {
		t.Fatalf("métricas: %d %s", r.Status, r.Raw)
	}
	var cpu float64
	var memUsed, rx int64
	if err := e.pool.QueryRow(context.Background(), `SELECT cpu_usage_percent, memory_used_bytes, network_rx_bytes_total
		FROM server_metrics WHERE server_id=$1`, srvA).Scan(&cpu, &memUsed, &rx); err != nil || cpu != 12.5 || memUsed != 400 || rx != 1000 {
		t.Errorf("persistência: cpu=%v mem=%v rx=%v err=%v", cpu, memUsed, rx, err)
	}
	// reenvio é idempotente
	r = e.do("POST", "/api/v1/agent/metrics", token, payload(ts))
	if r.Status != 200 || r.data()["duplicate"] != true || e.count(`SELECT count(*) FROM server_metrics WHERE server_id=$1`, srvA) != 1 {
		t.Errorf("duplicata: %d %s", r.Status, r.Raw)
	}
	// o agente não consegue escolher o servidor: campo desconhecido é rejeitado
	r = e.do("POST", "/api/v1/agent/metrics", token, payload(now, func(p map[string]any) { p["server_id"] = srvB }))
	if r.Status != 400 {
		t.Errorf("server_id no payload deveria ser rejeitado: %d %s", r.Status, r.Raw)
	}
	if e.count(`SELECT count(*) FROM server_metrics WHERE server_id=$1`, srvB) != 0 {
		t.Error("nada pode ser gravado em outro servidor")
	}

	// validações
	bad := map[string]func(map[string]any){
		"cpu>100":      func(p map[string]any) { p["cpu"].(map[string]any)["usage_percent"] = 101 },
		"futuro":       func(p map[string]any) { p["collected_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339) },
		"antigo":       func(p map[string]any) { p["collected_at"] = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339) },
		"mem inválida": func(p map[string]any) { p["memory"].(map[string]any)["used_bytes"] = 5000 },
		"tipo errado":  func(p map[string]any) { p["agent_version"] = 7 },
		"disco dup":    func(p map[string]any) { d := p["disks"].([]any); p["disks"] = append(d, d[0]) },
	}
	for name, mut := range bad {
		r := e.do("POST", "/api/v1/agent/metrics", token, payload(now.Add(time.Second), mut))
		if r.Status != 422 {
			t.Errorf("%s: esperava 422, obteve %d %s", name, r.Status, r.Raw)
		}
	}
	if r := e.do("POST", "/api/v1/agent/metrics", token, strings.Repeat("x", 70<<10)); r.Status != 413 && r.Status != 400 {
		t.Errorf("corpo grande: %d", r.Status)
	}

	// discos: upsert sem duplicar, ordem de chegada e remoção de volumes ausentes
	disks := e.admin("GET", "/api/v1/servers/"+srvA+"/disks", nil).list()
	if len(disks) != 2 || disks[1].(map[string]any)["used_percent"] != float64(25) {
		t.Errorf("discos: %v", disks)
	}
	newer := now.Add(-2 * time.Second)
	e.do("POST", "/api/v1/agent/metrics", token, payload(newer, func(p map[string]any) {
		p["disks"] = []any{map[string]any{"mount_point": "/", "filesystem": "ext4", "total_bytes": 1000, "used_bytes": 900, "available_bytes": 100}}
	}))
	disks = e.admin("GET", "/api/v1/servers/"+srvA+"/disks", nil).list()
	if len(disks) != 1 || disks[0].(map[string]any)["used_bytes"] != float64(900) {
		t.Errorf("volume ausente deveria ser removido e / atualizado: %v", disks)
	}
	// amostra mais antiga que a já gravada não sobrescreve
	e.do("POST", "/api/v1/agent/metrics", token, payload(now.Add(-4*time.Second), func(p map[string]any) {
		p["disks"] = []any{map[string]any{"mount_point": "/", "filesystem": "ext4", "total_bytes": 1000, "used_bytes": 100, "available_bytes": 900}}
	}))
	disks = e.admin("GET", "/api/v1/servers/"+srvA+"/disks", nil).list()
	if len(disks) != 1 || disks[0].(map[string]any)["used_bytes"] != float64(900) {
		t.Errorf("amostra antiga sobrescreveu o disco: %v", disks)
	}

	// revogação
	if r := e.admin("DELETE", "/api/v1/servers/"+srvA+"/agent-credentials/"+credID, nil); r.Status != 204 {
		t.Fatalf("revogar: %d", r.Status)
	}
	if r := e.do("GET", "/api/v1/agent/config", token, nil); r.Status != 401 {
		t.Errorf("credencial revogada: %d", r.Status)
	}
	if r := e.admin("DELETE", "/api/v1/servers/"+srvA+"/agent-credentials/"+credID, nil); r.Status != 404 {
		t.Errorf("revogar de novo: %d", r.Status)
	}
	// credencial de A não pode ser revogada pela rota de B
	credB, _ := e.issue(srvB, nil)
	if r := e.admin("DELETE", "/api/v1/servers/"+srvA+"/agent-credentials/"+credB, nil); r.Status != 404 {
		t.Errorf("revogação cruzada: %d", r.Status)
	}
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE action IN ('agent_credential.create','agent_credential.revoke')`); n < 3 {
		t.Errorf("auditoria de credenciais: %d", n)
	}
}

func TestCredentialLifecycleRules(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")

	// substituição revoga as anteriores
	_, old := e.issue(id, nil)
	_, fresh := e.issue(id, map[string]any{"replace": true})
	if e.do("GET", "/api/v1/agent/config", old, nil).Status != 401 {
		t.Error("credencial substituída deveria ser rejeitada")
	}
	if e.do("GET", "/api/v1/agent/config", fresh, nil).Status != 200 {
		t.Error("nova credencial deveria funcionar")
	}

	// expiração
	credExp, tokExp := e.issue(id, map[string]any{"expires_in_days": 1})
	if e.do("GET", "/api/v1/agent/config", tokExp, nil).Status != 200 {
		t.Error("credencial ainda válida")
	}
	if _, err := e.pool.Exec(context.Background(), `UPDATE agent_credentials SET expires_at = now() - interval '1 second' WHERE id=$1`, credExp); err != nil {
		t.Fatal(err)
	}
	if e.do("GET", "/api/v1/agent/config", tokExp, nil).Status != 401 {
		t.Error("credencial expirada deveria ser rejeitada")
	}
	for _, bad := range []any{map[string]any{"expires_in_days": 0}, map[string]any{"expires_in_days": 99999}} {
		if r := e.admin("POST", "/api/v1/servers/"+id+"/agent-credentials", bad); r.Status != 422 {
			t.Errorf("expires_in_days inválido: %d", r.Status)
		}
	}

	// servidor desativado => 403; reativado => volta a funcionar
	e.admin("PATCH", "/api/v1/servers/"+id, map[string]string{"status": "disabled"})
	if r := e.do("GET", "/api/v1/agent/config", fresh, nil); r.Status != 403 || r.errCode() != "SERVER_DISABLED" {
		t.Errorf("servidor desativado: %d %s", r.Status, r.Raw)
	}
	e.admin("PATCH", "/api/v1/servers/"+id, map[string]string{"status": "maintenance"})
	if e.do("GET", "/api/v1/agent/config", fresh, nil).Status != 200 {
		t.Error("em manutenção o agente continua enviando")
	}

	// exclusão do servidor revoga credenciais e preserva histórico
	if r := e.do("POST", "/api/v1/agent/metrics", fresh, payload(time.Now().Add(-time.Second))); r.Status != 200 {
		t.Fatalf("métricas: %d %s", r.Status, r.Raw)
	}
	e.admin("DELETE", "/api/v1/servers/"+id, nil)
	if e.do("GET", "/api/v1/agent/config", fresh, nil).Status != 401 {
		t.Error("servidor excluído: credencial deveria ser inválida")
	}
	if e.count(`SELECT count(*) FROM server_metrics WHERE server_id=$1`, id) != 1 {
		t.Error("histórico de métricas deve ser preservado na exclusão lógica")
	}
	if e.count(`SELECT count(*) FROM agent_credentials WHERE server_id=$1 AND revoked_at IS NULL`, id) != 0 {
		t.Error("todas as credenciais deveriam estar revogadas")
	}
}

func TestConnectionStatusIsComputed(t *testing.T) {
	e := newEnv(t, adminKey)
	on, off, never := e.createServer("on"), e.createServer("off"), e.createServer("never")
	ctx := context.Background()
	_, _ = e.pool.Exec(ctx, `UPDATE servers SET last_seen_at = now() - interval '10 seconds' WHERE id=$1`, on)
	_, _ = e.pool.Exec(ctx, `UPDATE servers SET last_seen_at = now() - interval '5 minutes' WHERE id=$1`, off)
	_ = never

	conn := func(id string) any { return e.admin("GET", "/api/v1/servers/"+id, nil).data()["connection_status"] }
	if conn(on) != "online" || conn(off) != "offline" || conn(never) != "unknown" {
		t.Errorf("on=%v off=%v never=%v", conn(on), conn(off), conn(never))
	}
	for f, want := range map[string]string{"online": "on", "offline": "off", "unknown": "never"} {
		r := e.admin("GET", "/api/v1/servers?connection="+f, nil)
		if len(r.list()) != 1 || r.list()[0].(map[string]any)["name"] != want {
			t.Errorf("filtro %s: %s", f, r.Raw)
		}
	}
	// sem nenhum UPDATE manual de status: o estado muda apenas com o tempo
	_, _ = e.pool.Exec(ctx, `UPDATE servers SET last_seen_at = now() WHERE id=$1`, off)
	if conn(off) != "online" {
		t.Error("deveria voltar a online sem alteração de status")
	}
}

func TestAgentRateLimited(t *testing.T) {
	e := newEnvRate(t, adminKey, 2, 10) // padrões de produção
	_, tok := e.issue(e.createServer("srv"), nil)
	limited := 0
	for i := 0; i < 30; i++ {
		r := e.do("GET", "/api/v1/agent/config", tok, nil)
		if r.Status == 429 {
			limited++
			if r.Header.Get("Retry-After") == "" || r.errCode() != "RATE_LIMITED" {
				t.Fatalf("429 sem Retry-After/código: %v %s", r.Header, r.Raw)
			}
		}
	}
	if limited == 0 {
		t.Error("rajada de 30 requisições deveria ser limitada")
	}
}

func TestConcurrentIngestIsIdempotent(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	repo := metrics.NewRepository(e.pool)

	build := func(ts time.Time) metrics.Payload {
		cpu, up := 10.0, int64(5)
		return metrics.Payload{
			AgentVersion: "t", CollectedAt: ts.UTC().Truncate(time.Millisecond),
			Host:   metrics.Host{UptimeSeconds: &up},
			CPU:    metrics.CPU{UsagePercent: &cpu},
			Memory: metrics.Memory{TotalBytes: 10, UsedBytes: 5, AvailableBytes: 5},
			Disks:  []metrics.Disk{{MountPoint: "/", Filesystem: "ext4", TotalBytes: 10, UsedBytes: 5, AvailableBytes: 5}},
		}
	}
	same := build(time.Now().Add(-time.Minute))
	var stored atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.Ingest(context.Background(), id, same)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				stored.Add(1)
			}
		}()
	}
	wg.Wait()
	if stored.Load() != 1 || e.count(`SELECT count(*) FROM server_metrics WHERE server_id=$1`, id) != 1 {
		t.Errorf("mesma amostra concorrente: stored=%d", stored.Load())
	}

	// amostras distintas concorrentes são todas gravadas, e discos não duplicam
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := repo.Ingest(context.Background(), id, build(time.Now().Add(-time.Duration(i+2)*time.Second))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if n := e.count(`SELECT count(*) FROM server_metrics WHERE server_id=$1`, id); n != 21 {
		t.Errorf("amostras distintas: %d (esperado 21)", n)
	}
	if n := e.count(`SELECT count(*) FROM server_disks WHERE server_id=$1`, id); n != 1 {
		t.Errorf("discos duplicados: %d", n)
	}
}
