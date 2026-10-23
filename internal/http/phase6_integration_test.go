//go:build integration

package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/audit"
	"sentinela/internal/auth"
	"sentinela/internal/config"
	"sentinela/internal/events"
	"sentinela/internal/users"
)

const strongPw = "orquidea-azul-montanha-77"

var actorSeq atomic.Int32

// actor é um usuário real com seu próprio navegador (cookie jar) e token CSRF.
type actor struct {
	e        *env
	t        *testing.T
	ID       string
	Email    string
	Password string
	Role     string
	client   *nethttp.Client
	csrf     string
	headers  map[string]string // cabeçalhos extras em todas as requisições (ex.: X-Real-IP)
}

func (e *env) newActor(role string) *actor {
	e.t.Helper()
	n := actorSeq.Add(1)
	email := fmt.Sprintf("%s%d@exemplo.com", role, n)
	u, err := e.auth.CreateUser(context.Background(), audit.Context{Actor: "teste"},
		users.CreateInput{Name: fmt.Sprintf("Pessoa %s", role), Email: email, Role: role, Password: strongPw})
	if err != nil {
		e.t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	return &actor{e: e, t: e.t, ID: u.ID, Email: email, Password: strongPw, Role: role,
		client: &nethttp.Client{Jar: jar, CheckRedirect: func(*nethttp.Request, []*nethttp.Request) error { return nethttp.ErrUseLastResponse }}}
}

func (a *actor) raw(method, path string, body any, withCSRF bool, extra map[string]string) resp {
	a.t.Helper()
	var rdr io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rdr = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
	}
	req, _ := nethttp.NewRequest(method, a.e.srv.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF && a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	res, err := a.client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, Raw: string(raw)}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func (a *actor) do(method, path string, body any) resp { return a.raw(method, path, body, true, nil) }

func (a *actor) login() resp {
	a.t.Helper()
	r := a.raw("POST", "/api/v1/auth/login", map[string]string{"email": a.Email, "password": a.Password}, false, nil)
	if r.Status == 200 {
		a.csrf, _ = r.data()["csrf_token"].(string)
	}
	return r
}

func (a *actor) mustLogin() *actor {
	a.t.Helper()
	if r := a.login(); r.Status != 200 {
		a.t.Fatalf("login de %s: %d %s", a.Email, r.Status, r.Raw)
	}
	return a
}

func (a *actor) cookie() string {
	u, _ := url.Parse(a.e.srv.URL)
	for _, c := range a.client.Jar.Cookies(u) {
		if strings.HasSuffix(c.Name, "sentinela_session") {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

func TestLoginMeLogoutFlowAndCookieSecurity(t *testing.T) {
	e := newEnv(t, adminKey)
	a := e.newActor("operator")

	r := a.login()
	if r.Status != 200 || r.data()["via"] != "session" || r.data()["csrf_token"] == "" || fnum(r.data(), "user", "email") != a.Email ||
		fnum(r.data(), "user", "role") != "operator" || r.data()["expires_at"] == nil || r.data()["idle_expires_at"] == nil {
		t.Fatalf("login: %d %s", r.Status, r.Raw)
	}
	for _, leak := range []string{`"password"`, "password_hash", "argon2", strongPw} {
		if strings.Contains(r.Raw, leak) {
			t.Errorf("a resposta do login não pode conter %q: %s", leak, r.Raw)
		}
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control: %q", r.Header.Get("Cache-Control"))
	}
	ck := r.Header.Values("Set-Cookie")
	if len(ck) != 1 {
		t.Fatalf("Set-Cookie: %v", ck)
	}
	c := ck[0]
	for _, want := range []string{"sentinela_session=ses_", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=", "Expires="} {
		if !strings.Contains(c, want) {
			t.Errorf("cookie sem %q: %s", want, c)
		}
	}
	if strings.Contains(c, "Domain=") {
		t.Errorf("o cookie não deve ter Domain: %s", c)
	}
	token := strings.TrimPrefix(strings.SplitN(c, ";", 2)[0], "sentinela_session=")
	if strings.Contains(r.Raw, token) {
		t.Error("o token da sessão nunca vai no corpo (só no cookie HttpOnly)")
	}

	// /auth/me reemite o mesmo token CSRF (derivado da sessão), útil após recarregar a página
	me := a.do("GET", "/api/v1/auth/me", nil)
	if me.Status != 200 || me.data()["csrf_token"] != a.csrf || fnum(me.data(), "user", "id") != a.ID {
		t.Errorf("me: %s", me.Raw)
	}
	if r := (&actor{e: e, t: t, client: &nethttp.Client{}}).raw("GET", "/api/v1/auth/me", nil, false, nil); r.Status != 401 {
		t.Errorf("sem cookie: %d", r.Status)
	}

	saved := a.cookie()
	out := a.do("POST", "/api/v1/auth/logout", nil)
	if out.Status != 204 {
		t.Fatalf("logout: %d %s", out.Status, out.Raw)
	}
	if cc := out.Header.Get("Set-Cookie"); !strings.Contains(cc, "sentinela_session=;") && !strings.Contains(cc, "Max-Age=0") && !strings.Contains(cc, "Max-Age=-1") {
		t.Errorf("logout deve limpar o cookie: %q", cc)
	}
	// repetir o cookie roubado/antigo depois do logout não funciona (revogação no servidor)
	replay := (&actor{e: e, t: t, client: &nethttp.Client{}}).raw("GET", "/api/v1/auth/me", nil, false, map[string]string{"Cookie": saved})
	if replay.Status != 401 {
		t.Errorf("sessão revogada ainda aceita: %d", replay.Status)
	}
	// o servidor manda limpar o cookie inválido
	if !strings.Contains(strings.Join(replay.Header.Values("Set-Cookie"), ";"), "Max-Age") {
		t.Error("cookie inválido deveria ser limpo")
	}
}

func TestLoginErrorsAreUniformAndInputIsStrict(t *testing.T) {
	e := newEnv(t, adminKey)
	a := e.newActor("viewer")
	off := e.newActor("viewer")
	f := false
	e.auth.UpdateUser(context.Background(), audit.Context{Actor: "t"}, off.ID, users.UpdateInput{IsActive: &f})
	anon := &actor{e: e, t: t, client: &nethttp.Client{}, headers: map[string]string{}}

	var msgs []string
	for i, c := range []map[string]string{
		{"email": a.Email, "password": "senha-errada-qualquer-1"}, // senha errada
		{"email": "ninguem@exemplo.com", "password": strongPw},    // e-mail inexistente
		{"email": off.Email, "password": strongPw},                // desativado, senha certa
		{"email": "isto-nao-e-email", "password": strongPw},
	} {
		anon.headers["X-Real-IP"] = "" // sem proxy confiável: o IP é o da conexão
		r := anon.raw("POST", "/api/v1/auth/login", c, false, nil)
		if r.Status != 401 || r.errCode() != "INVALID_CREDENTIALS" {
			t.Fatalf("caso %d: %d %s", i, r.Status, r.Raw)
		}
		if len(r.Header.Values("Set-Cookie")) != 0 {
			t.Errorf("caso %d: login falho não pode definir cookie", i)
		}
		msgs = append(msgs, r.Raw)
		e.exec(`DELETE FROM login_attempts`) // não deixa o bloqueio interferir neste teste
	}
	for _, m := range msgs[1:] {
		if m != msgs[0] {
			t.Errorf("as respostas de falha devem ser idênticas (sem enumeração):\n%s\n%s", msgs[0], m)
		}
	}
	if r := anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": "", "password": ""}, false, nil); r.Status != 422 {
		t.Errorf("campos vazios: %d", r.Status)
	}
	if r := anon.raw("POST", "/api/v1/auth/login", `{"email":"a@b.com","password":"x","admin":true}`, false, nil); r.Status != 400 {
		t.Errorf("campo desconhecido: %d", r.Status)
	}
	if r := anon.raw("POST", "/api/v1/auth/login", `{`, false, nil); r.Status != 400 {
		t.Errorf("JSON inválido: %d", r.Status)
	}
	if r := anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": a.Email, "password": strings.Repeat("x", 5000)}, false, nil); r.Status != 422 {
		t.Errorf("senha acima de 1 KiB (evita DoS no hash): %d", r.Status)
	}
	if r := anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": a.Email, "password": strings.Repeat("x", 20000)}, false, nil); r.Status != 413 {
		t.Errorf("corpo acima de 8 KiB: %d", r.Status)
	}
	if r := anon.raw("GET", "/api/v1/auth/login", nil, false, nil); r.Status != 405 {
		t.Errorf("GET no login: %d", r.Status)
	}
}

func TestCSRFAndOriginProtection(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) { c.CORSAllowedOrigins = []string{"https://painel.exemplo.com"} })
	admin := e.newActor("admin").mustLogin()
	other := e.newActor("admin").mustLogin()
	body := map[string]string{"name": "srv-csrf", "hostname": "srv-csrf.example.com"}

	if r := admin.raw("POST", "/api/v1/servers", body, false, nil); r.Status != 403 || r.errCode() != "CSRF_INVALID" {
		t.Errorf("sem token CSRF: %d %s", r.Status, r.Raw)
	}
	if r := admin.raw("POST", "/api/v1/servers", body, false, map[string]string{"X-CSRF-Token": "xyz"}); r.Status != 403 || r.errCode() != "CSRF_INVALID" {
		t.Errorf("token CSRF errado: %d", r.Status)
	}
	// o token de OUTRA sessão não vale (é derivado da sessão)
	if r := admin.raw("POST", "/api/v1/servers", body, false, map[string]string{"X-CSRF-Token": other.csrf}); r.Status != 403 {
		t.Errorf("CSRF de outra sessão: %d", r.Status)
	}
	if e.count(`SELECT count(*) FROM servers`) != 0 {
		t.Fatal("nada pode ter sido criado sem CSRF válido")
	}
	// métodos de leitura não exigem CSRF
	if r := admin.raw("GET", "/api/v1/servers", nil, false, nil); r.Status != 200 {
		t.Errorf("GET: %d", r.Status)
	}
	// com token correto, passa (mesma origem: sem cabeçalho Origin ou com o mesmo host)
	u, _ := url.Parse(e.srv.URL)
	if r := admin.raw("POST", "/api/v1/servers", body, true, map[string]string{"Origin": "http://" + u.Host}); r.Status != 201 {
		t.Errorf("mesma origem: %d %s", r.Status, r.Raw)
	}
	// origem estranha é recusada mesmo com CSRF correto; origem configurada passa
	body2 := map[string]string{"name": "srv-csrf2", "hostname": "srv-csrf2.example.com"}
	for _, origin := range []string{"https://evil.com", "null", "http://" + u.Host + ".evil.com"} {
		if r := admin.raw("POST", "/api/v1/servers", body2, true, map[string]string{"Origin": origin}); r.Status != 403 || r.errCode() != "ORIGIN_NOT_ALLOWED" {
			t.Errorf("origem %q: %d %s", origin, r.Status, r.Raw)
		}
	}
	if r := admin.raw("POST", "/api/v1/servers", body2, true, map[string]string{"Origin": "https://painel.exemplo.com"}); r.Status != 201 {
		t.Errorf("origem configurada: %d %s", r.Status, r.Raw)
	}
	// chave de API não é credencial de navegador: não usa cookie, logo não precisa de CSRF
	if r := e.admin("POST", "/api/v1/servers", map[string]string{"name": "via-chave", "hostname": "k.example.com"}); r.Status != 201 {
		t.Errorf("chave de API: %d", r.Status)
	}
	// um cookie válido NÃO é aceito se um Authorization inválido acompanha a requisição
	r := admin.raw("GET", "/api/v1/servers", nil, false, map[string]string{"Authorization": "Bearer lixo"})
	if r.Status != 401 {
		t.Errorf("Authorization inválido não deve cair para o cookie: %d", r.Status)
	}
}

// A matriz é gerada a partir das rotas REGISTRADAS: uma rota nova sem proteção quebra este teste.
func TestAuthorizationMatrixCoversEveryRoute(t *testing.T) {
	e := newEnv(t, adminKey)
	viewer, operator, admin := e.newActor("viewer").mustLogin(), e.newActor("operator").mustLogin(), e.newActor("admin").mustLogin()
	byRole := map[auth.Role]*actor{auth.Viewer: viewer, auth.Operator: operator, auth.Admin: admin}
	anon := &actor{e: e, t: t, client: &nethttp.Client{}}
	zero := "00000000-0000-0000-0000-000000000000"
	fill := func(p string) string {
		return strings.NewReplacer("{id}", zero, "{credentialId}", zero).Replace(p)
	}

	routes := append([]apphttpRoute(nil), registryRoutes(e)...)
	if len(routes) < 50 {
		t.Fatalf("poucas rotas registradas (%d): o registro deveria cobrir toda a API", len(routes))
	}
	checked := map[string]int{}
	for _, rt := range routes {
		path := fill(rt.Path)
		switch rt.Kind {
		case "public":
			continue // login é testado à parte
		case "agent":
			if r := anon.raw(rt.Method, path, `{}`, false, nil); r.Status != 401 {
				t.Errorf("rota de agente %s %s sem credencial: %d", rt.Method, rt.Path, r.Status)
			}
			if r := admin.raw(rt.Method, path, `{}`, true, nil); r.Status != 401 {
				t.Errorf("rota de agente %s %s com sessão de admin: %d (deve exigir token de agente)", rt.Method, rt.Path, r.Status)
			}
			checked["agent"]++
			continue
		}
		label := rt.Method + " " + rt.Path
		body := any(nil)
		if rt.Method != "GET" {
			body = `{}`
		}
		// 1) sem autenticação => 401
		if r := anon.raw(rt.Method, path, body, false, nil); r.Status != 401 {
			t.Errorf("%s sem autenticação: %d (esperado 401)", label, r.Status)
		}
		// 2) papéis insuficientes => 403 (a requisição nem chega ao handler)
		for _, role := range []auth.Role{auth.Viewer, auth.Operator, auth.Admin} {
			if role.AtLeast(rt.Role) {
				continue
			}
			if rt.Path == "/api/v1/events" {
				continue
			}
			r := byRole[role].do(rt.Method, path, body)
			if r.Status != 403 || r.errCode() != "FORBIDDEN" {
				t.Errorf("%s com papel %s (exige %s): %d %s", label, role, rt.Role, r.Status, r.Raw)
			}
			checked["negado"]++
		}
		// 3) papel suficiente => nunca 401/403 (o handler decide: 200, 404, 422...)
		if rt.Path == "/api/v1/events" || rt.Path == "/api/v1/auth/logout" || rt.Path == "/api/v1/auth/logout-all" {
			continue // abrem stream / encerram a própria sessão: cobertos em testes dedicados
		}
		for _, role := range []auth.Role{auth.Viewer, auth.Operator, auth.Admin} {
			if !role.AtLeast(rt.Role) {
				continue
			}
			r := byRole[role].do(rt.Method, path, body)
			// 503 LOGS_UNAVAILABLE é a resposta documentada do handler quando o ClickHouse não está configurado
			if r.Status == 401 || r.Status == 403 || (r.Status >= 500 && r.errCode() != "LOGS_UNAVAILABLE") {
				t.Errorf("%s com papel %s (suficiente): %d %s", label, role, r.Status, r.Raw)
			}
			checked["permitido"]++
		}
	}
	t.Logf("matriz: %d rotas; verificações %v", len(routes), checked)
	if checked["negado"] < 35 || checked["permitido"] < 90 || checked["agent"] != 10 {
		t.Errorf("cobertura da matriz: %v", checked)
	}

	// o router não pode ter rotas /api/v1 fora do registro (rota esquecida = rota sem papel declarado)
	registered := map[string]bool{}
	for _, rt := range routes {
		registered[rt.Method+" "+rt.Path] = true
	}
	err := chi.Walk(e.router(e.hub).(chi.Routes), func(method, route string, _ nethttp.Handler, _ ...func(nethttp.Handler) nethttp.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if strings.HasPrefix(route, "/api/v1") && !registered[method+" "+route] {
			t.Errorf("rota %s %s não está no registro de permissões", method, route)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// papéis de cada categoria de recurso (documenta a política)
	want := map[string]auth.Role{
		"GET /api/v1/servers": auth.Viewer, "POST /api/v1/servers": auth.Admin,
		"POST /api/v1/alerts/{id}/acknowledge": auth.Operator, "GET /api/v1/notification-channels": auth.Admin,
		"GET /api/v1/servers/{id}/agent-credentials": auth.Admin, "GET /api/v1/users": auth.Admin, "GET /api/v1/audit-logs": auth.Admin,
		"GET /api/v1/events": auth.Viewer,
	}
	for _, rt := range routes {
		if w, ok := want[rt.Method+" "+rt.Path]; ok && rt.Role != w {
			t.Errorf("%s %s exige %s (esperado %s)", rt.Method, rt.Path, rt.Role, w)
		}
	}
}

type apphttpRoute struct {
	Method, Path, Kind string
	Role               auth.Role
}

func registryRoutes(e *env) []apphttpRoute {
	e.reg.Mu().Lock()
	defer e.reg.Mu().Unlock()
	var out []apphttpRoute
	seen := map[string]bool{}
	for _, r := range e.reg.Routes {
		k := r.Method + " " + r.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, apphttpRoute{r.Method, r.Path, r.Kind, r.Role})
	}
	return out
}

func TestCredentialsDoNotCrossBoundaries(t *testing.T) {
	e := newEnv(t, adminKey)
	admin := e.newActor("admin").mustLogin()
	srv := e.createServer("srv")
	_, agentTok := e.issue(srv, nil)
	// token de agente nas rotas de usuário
	if r := e.do("GET", "/api/v1/servers", agentTok, nil); r.Status != 401 {
		t.Errorf("token de agente em rota de usuário: %d", r.Status)
	}
	// sessão de usuário e chave de API nas rotas de agente
	if r := admin.do("GET", "/api/v1/agent/config", nil); r.Status != 401 {
		t.Errorf("sessão em rota de agente: %d", r.Status)
	}
	if r := e.do("GET", "/api/v1/agent/config", adminKey, nil); r.Status != 401 {
		t.Errorf("chave de API em rota de agente: %d", r.Status)
	}
	// o cookie de sessão não é aceito como Bearer
	if r := e.do("GET", "/api/v1/servers", strings.TrimPrefix(admin.cookie(), "sentinela_session="), nil); r.Status != 401 {
		t.Errorf("token de sessão como Bearer: %d", r.Status)
	}
}

func TestUsersAPI(t *testing.T) {
	e := newEnv(t, adminKey)
	admin := e.newActor("admin").mustLogin()
	viewer := e.newActor("viewer").mustLogin()

	// só administradores gerenciam usuários
	for _, rq := range [][2]string{{"GET", "/api/v1/users"}, {"POST", "/api/v1/users"}, {"GET", "/api/v1/users/" + viewer.ID}, {"PATCH", "/api/v1/users/" + viewer.ID}, {"GET", "/api/v1/audit-logs"}} {
		if r := viewer.do(rq[0], rq[1], `{}`); r.Status != 403 {
			t.Errorf("%s %s como viewer: %d", rq[0], rq[1], r.Status)
		}
	}

	r := admin.do("POST", "/api/v1/users", map[string]string{"name": "Bia Souza", "email": "  BIA@Exemplo.com ", "role": "operator", "password": "violeta-quente-rio-2026"})
	if r.Status != 201 || r.data()["email"] != "bia@exemplo.com" || r.data()["role"] != "operator" || r.data()["is_active"] != true ||
		!strings.HasPrefix(r.Header.Get("Location"), "/api/v1/users/") {
		t.Fatalf("criar: %d %s", r.Status, r.Raw)
	}
	for _, leak := range []string{`"password"`, "password_hash", "argon2", "violeta-quente"} {
		if strings.Contains(r.Raw, leak) {
			t.Errorf("resposta contém %q: %s", leak, r.Raw)
		}
	}
	bia := r.data()["id"].(string)

	bad := map[string]map[string]string{
		"senha fraca":   {"name": "X Y", "email": "x@exemplo.com", "role": "viewer", "password": "password1234"},
		"senha curta":   {"name": "X Y", "email": "x@exemplo.com", "role": "viewer", "password": "curta"},
		"e-mail":        {"name": "X Y", "email": "nao-e-email", "role": "viewer", "password": "violeta-quente-rio-2026"},
		"papel":         {"name": "X Y", "email": "x@exemplo.com", "role": "root", "password": "violeta-quente-rio-2026"},
		"sem nome":      {"name": "", "email": "x@exemplo.com", "role": "viewer", "password": "violeta-quente-rio-2026"},
		"senha = email": {"name": "X Y", "email": "joaozinho@exemplo.com", "role": "viewer", "password": "joaozinho-forte-123"},
	}
	for name, b := range bad {
		if r := admin.do("POST", "/api/v1/users", b); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := admin.do("POST", "/api/v1/users", map[string]string{"name": "Dup", "email": "BIA@exemplo.com", "role": "viewer", "password": "violeta-quente-rio-2026"}); r.Status != 409 {
		t.Errorf("e-mail duplicado: %d", r.Status)
	}
	if r := admin.do("POST", "/api/v1/users", `{"name":"X","email":"x@exemplo.com","role":"viewer","password":"violeta-quente-rio-2026","is_active":false}`); r.Status != 400 {
		t.Errorf("campo desconhecido: %d", r.Status)
	}

	if l := admin.do("GET", "/api/v1/users", nil); l.Status != 200 || l.meta()["total"] != float64(3) {
		t.Errorf("lista: %s", l.Raw)
	}
	for q, want := range map[string]int{"role=admin": 1, "role=operator": 1, "q=bia": 1, "q=%25": 0, "is_active=true": 3, "is_active=false": 0, "per_page=2": 2} {
		if l := admin.do("GET", "/api/v1/users?"+q, nil); l.Status != 200 || len(l.list()) != want {
			t.Errorf("%s: %d (esperado %d)", q, len(l.list()), want)
		}
	}
	for _, q := range []string{"role=x", "is_active=talvez", "per_page=0"} {
		if l := admin.do("GET", "/api/v1/users?"+q, nil); l.Status != 422 {
			t.Errorf("%s: %d", q, l.Status)
		}
	}
	if g := admin.do("GET", "/api/v1/users/"+bia, nil); g.Status != 200 || g.data()["name"] != "Bia Souza" {
		t.Errorf("get: %s", g.Raw)
	}
	if g := admin.do("GET", "/api/v1/users/00000000-0000-0000-0000-000000000000", nil); g.Status != 404 {
		t.Errorf("inexistente: %d", g.Status)
	}
	if g := admin.do("GET", "/api/v1/users/xyz", nil); g.Status != 400 {
		t.Errorf("id inválido: %d", g.Status)
	}

	// o papel vale na PRÓXIMA requisição, sem novo login
	bi := &actor{e: e, t: t, Email: "bia@exemplo.com", Password: "violeta-quente-rio-2026", client: &nethttp.Client{}}
	bi.client.Jar, _ = cookiejar.New(nil)
	bi.mustLogin()
	zero := "00000000-0000-0000-0000-000000000000"
	if r := bi.do("POST", "/api/v1/alerts/"+zero+"/acknowledge", `{}`); r.Status != 404 { // operador passa da autorização
		t.Fatalf("operador reconhece alerta: %d", r.Status)
	}
	if r := admin.do("PATCH", "/api/v1/users/"+bia, map[string]string{"role": "viewer"}); r.Status != 200 {
		t.Fatal(r.Raw)
	}
	if r := bi.do("POST", "/api/v1/alerts/"+zero+"/acknowledge", `{}`); r.Status != 403 {
		t.Errorf("após o rebaixamento, a MESMA sessão deveria perder o acesso: %d", r.Status)
	}

	// desativar derruba a sessão na hora e impede novo login, mesmo com a senha certa
	r = admin.do("PATCH", "/api/v1/users/"+bia, map[string]any{"is_active": false})
	if r.Status != 200 || r.meta()["revoked_sessions"] != float64(1) {
		t.Errorf("desativar: %s", r.Raw)
	}
	if me := bi.do("GET", "/api/v1/auth/me", nil); me.Status != 401 {
		t.Errorf("sessão de usuário desativado: %d", me.Status)
	}
	if l := bi.login(); l.Status != 401 || l.errCode() != "INVALID_CREDENTIALS" {
		t.Errorf("login de desativado: %d %s", l.Status, l.Raw)
	}
	admin.do("PATCH", "/api/v1/users/"+bia, map[string]any{"is_active": true})
	bi.mustLogin()

	// redefinição de senha por um admin revoga as sessões e a senha antiga deixa de valer
	if r := admin.do("PATCH", "/api/v1/users/"+bia, map[string]string{"password": "password1234"}); r.Status != 422 {
		t.Errorf("redefinição com senha fraca: %d", r.Status)
	}
	if r := admin.do("PATCH", "/api/v1/users/"+bia, map[string]string{"password": "cacto-lunar-trovao-4410"}); r.Status != 200 || r.meta()["revoked_sessions"] != float64(1) {
		t.Errorf("redefinir: %s", r.Raw)
	}
	if me := bi.do("GET", "/api/v1/auth/me", nil); me.Status != 401 {
		t.Errorf("sessão anterior à redefinição: %d", me.Status)
	}
	if l := bi.login(); l.Status != 401 {
		t.Errorf("senha antiga: %d", l.Status)
	}
	bi.Password = "cacto-lunar-trovao-4410"
	bi.mustLogin()

	// revogação manual de sessões
	if r := admin.do("POST", "/api/v1/users/"+bia+"/sessions/revoke", nil); r.Status != 200 || r.data()["revoked_sessions"] != float64(1) {
		t.Errorf("revogar: %s", r.Raw)
	}
	if me := bi.do("GET", "/api/v1/auth/me", nil); me.Status != 401 {
		t.Errorf("sessão revogada pelo admin: %d", me.Status)
	}
	if r := admin.do("POST", "/api/v1/users/00000000-0000-0000-0000-000000000000/sessions/revoke", nil); r.Status != 404 {
		t.Errorf("revogar de inexistente: %d", r.Status)
	}

	// o último administrador nunca pode ser removido, nem por ele mesmo
	for _, patch := range []map[string]any{{"is_active": false}, {"role": "viewer"}} {
		if r := admin.do("PATCH", "/api/v1/users/"+admin.ID, patch); r.Status != 409 || r.errCode() != "LAST_ADMIN" {
			t.Errorf("último admin %v: %d %s", patch, r.Status, r.Raw)
		}
	}
	if me := admin.do("GET", "/api/v1/auth/me", nil); me.Status != 200 {
		t.Error("o admin deve continuar logado")
	}
}

func TestChangePasswordAndLogoutAllOverHTTP(t *testing.T) {
	e := newEnv(t, adminKey)
	a := e.newActor("operator").mustLogin()
	other := *a // segundo dispositivo do mesmo usuário
	other.client = &nethttp.Client{}
	other.client.Jar, _ = cookiejar.New(nil)
	other.mustLogin()

	if r := a.do("POST", "/api/v1/auth/change-password", map[string]string{"current_password": "errada-errada-errada-1", "new_password": "nova-senha-bem-longa-9"}); r.Status != 422 || !strings.Contains(r.Raw, "current_password") {
		t.Errorf("senha atual errada: %d %s", r.Status, r.Raw)
	}
	for name, np := range map[string]string{"fraca": "password1234", "curta": "abc", "igual": strongPw} {
		if r := a.do("POST", "/api/v1/auth/change-password", map[string]string{"current_password": strongPw, "new_password": np}); r.Status != 422 || !strings.Contains(r.Raw, "new_password") {
			t.Errorf("nova senha %s: %d %s", name, r.Status, r.Raw)
		}
	}
	if r := a.do("POST", "/api/v1/auth/change-password", map[string]string{"current_password": strongPw}); r.Status != 422 {
		t.Errorf("sem nova senha: %d", r.Status)
	}
	oldCookie := a.cookie()
	r := a.do("POST", "/api/v1/auth/change-password", map[string]string{"current_password": strongPw, "new_password": "nova-senha-bem-longa-9"})
	if r.Status != 200 || r.data()["csrf_token"] == "" || r.data()["csrf_token"] == a.csrf || len(r.Header.Values("Set-Cookie")) != 1 {
		t.Fatalf("trocar: %d %s", r.Status, r.Raw)
	}
	a.csrf = r.data()["csrf_token"].(string)
	if a.cookie() == oldCookie || a.cookie() == "" {
		t.Error("o token da sessão deve ser rotacionado")
	}
	if me := a.do("GET", "/api/v1/auth/me", nil); me.Status != 200 {
		t.Errorf("a sessão nova do dispositivo atual deve funcionar: %d", me.Status)
	}
	if me := other.do("GET", "/api/v1/auth/me", nil); me.Status != 401 {
		t.Errorf("a sessão do outro dispositivo deve ser revogada: %d", me.Status)
	}
	// logout em todos os dispositivos
	third := *a
	third.client = &nethttp.Client{}
	third.client.Jar, _ = cookiejar.New(nil)
	third.Password = "nova-senha-bem-longa-9"
	third.mustLogin()
	if r := a.do("POST", "/api/v1/auth/logout-all", nil); r.Status != 204 {
		t.Fatalf("logout-all: %d", r.Status)
	}
	if a.do("GET", "/api/v1/auth/me", nil).Status != 401 || third.do("GET", "/api/v1/auth/me", nil).Status != 401 {
		t.Error("todas as sessões deveriam estar revogadas")
	}
	// a chave de API não tem senha para trocar nem sessões para encerrar
	if r := e.admin("POST", "/api/v1/auth/change-password", map[string]string{"current_password": "x", "new_password": "y"}); r.Status != 400 {
		t.Errorf("chave de API trocando senha: %d", r.Status)
	}
	if r := e.admin("POST", "/api/v1/auth/logout-all", nil); r.Status != 400 {
		t.Errorf("chave de API em logout-all: %d", r.Status)
	}
	me := e.admin("GET", "/api/v1/auth/me", nil)
	if me.Status != 200 || me.data()["via"] != "api_key" || fnum(me.data(), "user", "role") != "admin" || me.data()["csrf_token"] != nil {
		t.Errorf("/auth/me com chave de API: %s", me.Raw)
	}
}

func TestBruteForceLockoutOverHTTP(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) { c.TrustProxy = true }) // IP do cliente via X-Real-IP
	victim := e.newActor("viewer")
	attacker := &actor{e: e, t: t, client: &nethttp.Client{}, headers: map[string]string{"X-Real-IP": "203.0.113.5"}}

	for i := 0; i < 5; i++ {
		r := attacker.raw("POST", "/api/v1/auth/login", map[string]string{"email": victim.Email, "password": fmt.Sprintf("chute-errado-%d-xyz", i)}, false, nil)
		if r.Status != 401 {
			t.Fatalf("tentativa %d: %d", i, r.Status)
		}
	}
	r := attacker.raw("POST", "/api/v1/auth/login", map[string]string{"email": victim.Email, "password": victim.Password}, false, nil) // senha CERTA
	if r.Status != 429 || r.errCode() != "LOGIN_LOCKED" {
		t.Fatalf("bloqueio: %d %s", r.Status, r.Raw)
	}
	if secs, _ := strconv.Atoi(r.Header.Get("Retry-After")); secs < 600 || secs > 900 {
		t.Errorf("Retry-After: %q", r.Header.Get("Retry-After"))
	}
	if len(r.Header.Values("Set-Cookie")) != 0 {
		t.Error("login bloqueado não pode criar sessão")
	}
	// o usuário legítimo, em outro IP, NÃO é prejudicado
	victim.headers = map[string]string{"X-Real-IP": "198.51.100.7"}
	if l := victim.login(); l.Status != 200 {
		t.Errorf("usuário legítimo bloqueado por um atacante: %d %s", l.Status, l.Raw)
	}
	// e-mails inexistentes também são limitados (não dá para sondar contas)
	ghost := &actor{e: e, t: t, client: &nethttp.Client{}, headers: map[string]string{"X-Real-IP": "203.0.113.99"}}
	for i := 0; i < 5; i++ {
		ghost.raw("POST", "/api/v1/auth/login", map[string]string{"email": "fantasma@exemplo.com", "password": "chute-chute-chute-1"}, false, nil)
	}
	if g := ghost.raw("POST", "/api/v1/auth/login", map[string]string{"email": "fantasma@exemplo.com", "password": strongPw}, false, nil); g.Status != 429 {
		t.Errorf("e-mail inexistente: %d", g.Status)
	}
}

func TestLoginEndpointIsRateLimited(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) { c.TrustProxy = true })
	c := &actor{e: e, t: t, client: &nethttp.Client{}, headers: map[string]string{"X-Real-IP": "203.0.113.77"}}
	limited := 0
	for i := 0; i < 25; i++ { // e-mails diferentes: não aciona o bloqueio por conta, só o limite de taxa do endpoint
		r := c.raw("POST", "/api/v1/auth/login", map[string]string{"email": fmt.Sprintf("u%d@exemplo.com", i), "password": "chute-chute-chute-1"}, false, nil)
		if r.Status == 429 && r.errCode() == "RATE_LIMITED" {
			limited++
			if r.Header.Get("Retry-After") == "" {
				t.Error("429 sem Retry-After")
			}
		}
	}
	if limited == 0 {
		t.Error("rajada de logins deveria ser limitada (protege a CPU contra Argon2id em massa)")
	}
}

func TestGeneralAPIRateLimit(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) { c.APIRateLimit, c.APIRateBurst = 2, 5 })
	limited := 0
	for i := 0; i < 20; i++ {
		if r := e.admin("GET", "/api/v1/servers", nil); r.Status == 429 {
			limited++
			if r.errCode() != "RATE_LIMITED" || r.Header.Get("Retry-After") == "" {
				t.Fatalf("429 mal formado: %s %v", r.Raw, r.Header)
			}
		}
	}
	if limited < 10 {
		t.Errorf("limite por IP não aplicado: %d de 20", limited)
	}
	if r := e.do("GET", "/healthz", "", nil); r.Status != 200 {
		t.Errorf("healthz fora do limite da API: %d", r.Status)
	}
}

func TestSecurityHeadersCachingAndMetricsToken(t *testing.T) {
	e := newEnv(t, adminKey)
	for _, p := range []string{"/healthz", "/api/v1/servers", "/api/v1/auth/me", "/rota-inexistente"} {
		r := e.do("GET", p, adminKey, nil)
		for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
			"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"} {
			if r.Header.Get(h) != want {
				t.Errorf("%s %s = %q", p, h, r.Header.Get(h))
			}
		}
		if r.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS só em produção", p)
		}
		if strings.HasPrefix(p, "/api/v1") && r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q", p, r.Header.Get("Cache-Control"))
		}
	}
	// 401 também leva os cabeçalhos
	if r := e.do("GET", "/api/v1/servers", "", nil); r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("cabeçalhos no 401")
	}
	// produção: HSTS
	prod := newEnvCfg(t, func(c *config.Config) { c.Env, c.CookieSecure = "production", true })
	if r := prod.do("GET", "/healthz", "", nil); !strings.Contains(r.Header.Get("Strict-Transport-Security"), "max-age=31536000") {
		t.Errorf("HSTS em produção: %q", r.Header.Get("Strict-Transport-Security"))
	}
	// /metrics com token
	tok := strings.Repeat("m", 24)
	m := newEnvCfg(t, func(c *config.Config) { c.MetricsToken = tok })
	if r := m.do("GET", "/metrics", "", nil); r.Status != 401 {
		t.Errorf("sem token: %d", r.Status)
	}
	if r := m.do("GET", "/metrics", "errado", nil); r.Status != 401 {
		t.Errorf("token errado: %d", r.Status)
	}
	if r := m.do("GET", "/metrics", tok, nil); r.Status != 200 || !strings.Contains(r.Raw, "sentinela_http_requests_total") {
		t.Errorf("com token: %d", r.Status)
	}
	if r := m.do("GET", "/healthz", "", nil); r.Status != 200 {
		t.Error("healthz continua aberto")
	}
	if r := e.do("GET", "/metrics", "", nil); r.Status != 200 {
		t.Error("sem METRICS_TOKEN o endpoint é aberto (restrinja no proxy)")
	}
}

func TestSSEWithSessionCookieAndRevalidation(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) { c.SSEHeartbeat = 150 * time.Millisecond })
	viewer := e.newActor("viewer").mustLogin()
	admin := e.newActor("admin").mustLogin()

	if c := openSSE(t, e.srv.URL, "/api/v1/events", "", nil); c.Status != 401 {
		t.Errorf("sem credencial: %d", c.Status)
	}
	c := openSSE(t, e.srv.URL, "/api/v1/events", "", map[string]string{"Cookie": viewer.cookie()}) // EventSource com withCredentials
	if c.Status != 200 {
		t.Fatalf("viewer com cookie: %d %s", c.Status, c.body)
	}
	srv := e.createServer("web-1")
	admin.do("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "maintenance"})
	if m := c.expect(events.TypeServerStatus); m.payload(t)["server_id"] != srv {
		t.Errorf("%s", m.Data)
	}

	// sessão revogada => o stream é encerrado (no próximo ping), sem esperar o cliente reconectar
	if r := admin.do("POST", "/api/v1/users/"+viewer.ID+"/sessions/revoke", nil); r.Status != 200 {
		t.Fatal(r.Raw)
	}
	if !c.waitClosed(3 * time.Second) {
		t.Fatal("stream de sessão revogada continua aberto")
	}
	// novo stream com a sessão revogada: recusado
	if c2 := openSSE(t, e.srv.URL, "/api/v1/events", "", map[string]string{"Cookie": viewer.cookie()}); c2.Status != 401 {
		t.Errorf("cookie revogado: %d", c2.Status)
	}

	// usuário desativado => stream encerrado
	op := e.newActor("operator").mustLogin()
	c3 := openSSE(t, e.srv.URL, "/api/v1/events", "", map[string]string{"Cookie": op.cookie()})
	if c3.Status != 200 {
		t.Fatal(c3.Status)
	}
	admin.do("PATCH", "/api/v1/users/"+op.ID, map[string]any{"is_active": false})
	if !c3.waitClosed(3 * time.Second) {
		t.Fatal("stream de usuário desativado continua aberto")
	}
	// a chave de API continua funcionando no stream
	k := openSSE(t, e.srv.URL, "/api/v1/events", adminKey, nil)
	if k.Status != 200 {
		t.Errorf("chave de API: %d", k.Status)
	}
}

func TestAuditTrailRecordsWhoDidWhatWithoutSecrets(t *testing.T) {
	e := newEnv(t, adminKey)
	admin := e.newActor("admin").mustLogin()
	op := e.newActor("operator").mustLogin()

	srv := admin.do("POST", "/api/v1/servers", map[string]string{"name": "web-1", "hostname": "web-1.example.com"})
	srvID := srv.data()["id"].(string)
	admin.do("POST", "/api/v1/servers/"+srvID+"/agent-credentials", nil)
	admin.do("POST", "/api/v1/users", map[string]string{"name": "Cris Lima", "email": "cris@exemplo.com", "role": "viewer", "password": "girassol-veloz-nuvem-5521"})
	admin.do("PATCH", "/api/v1/users/"+op.ID, map[string]string{"password": "barco-de-papel-aurora-8830"})
	op.Password = "barco-de-papel-aurora-8830"
	op.mustLogin()
	// operador reconhece um alerta: o autor real fica registrado
	e.sample(srvID, time.Now().UTC(), 97, 4, 500, 1000, nil, nil)
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id=$1`, srvID)
	e.rule("CPU", "cpu_usage_percent", ">", 90, "critical", 0, "")
	e.evaluator().Tick(context.Background())
	alertID := e.queryID(`SELECT id::text FROM alerts WHERE status='firing'`)
	ack := op.do("POST", "/api/v1/alerts/"+alertID+"/acknowledge", map[string]string{"note": "estou vendo"})
	if ack.Status != 200 || ack.data()["acknowledged_by"] != op.ID {
		t.Fatalf("acknowledged_by deveria ser o usuário: %s", ack.Raw)
	}
	incID := e.queryID(`SELECT incident_id::text FROM alerts WHERE id=$1`, alertID)
	if ev := e.admin("GET", "/api/v1/incidents/"+incID+"/events", nil); !strings.Contains(ev.Raw, "reconhecido por "+op.Email) {
		t.Errorf("o evento do incidente deve citar quem reconheceu: %s", ev.Raw)
	}
	// falhas e bloqueios ficam registrados sem a senha digitada
	anon := &actor{e: e, t: t, client: &nethttp.Client{}}
	anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": "alguem@exemplo.com", "password": "Senha-Digitada-Errada-123"}, false, nil)

	logs := admin.do("GET", "/api/v1/audit-logs?per_page=100", nil)
	if logs.Status != 200 || len(logs.list()) < 8 {
		t.Fatalf("auditoria: %d %s", logs.Status, logs.Raw)
	}
	byAction := map[string]map[string]any{}
	for _, it := range logs.list() {
		m := it.(map[string]any)
		byAction[m["action"].(string)] = m
	}
	for _, a := range []string{"auth.login", "server.create", "agent_credential.create", "user.create", "user.update", "alert.acknowledge"} {
		if byAction[a] == nil {
			t.Errorf("ação %s ausente da auditoria", a)
		}
	}
	if m := byAction["server.create"]; m["actor"] != admin.Email || m["actor_user_id"] != admin.ID || m["resource_id"] != srvID {
		t.Errorf("server.create: %v", m)
	}
	if m := byAction["alert.acknowledge"]; m["actor"] != op.Email || m["actor_user_id"] != op.ID {
		t.Errorf("alert.acknowledge: %v", m)
	}
	// ações feitas com a chave de API aparecem como api_key
	e.admin("POST", "/api/v1/servers", map[string]string{"name": "via-chave", "hostname": "k.example.com"})
	l2 := admin.do("GET", "/api/v1/audit-logs?action=server.create", nil)
	foundKey := false
	for _, it := range l2.list() {
		if m := it.(map[string]any); m["actor"] == "api_key" && m["actor_user_id"] == nil {
			foundKey = true
		}
	}
	if !foundKey {
		t.Error("ação por chave de API deve constar como api_key")
	}

	// filtros
	if r := admin.do("GET", "/api/v1/audit-logs?action=user.", nil); r.Status != 200 || len(r.list()) < 3 {
		t.Errorf("prefixo user.: %d", len(r.list()))
	} else {
		for _, it := range r.list() {
			if !strings.HasPrefix(it.(map[string]any)["action"].(string), "user.") {
				t.Errorf("prefixo vazou: %v", it)
			}
		}
	}
	if r := admin.do("GET", "/api/v1/audit-logs?actor_user_id="+op.ID, nil); len(r.list()) == 0 {
		t.Error("filtro por autor")
	}
	if r := admin.do("GET", "/api/v1/audit-logs?resource_type=server&resource_id="+srvID, nil); len(r.list()) < 2 {
		t.Errorf("filtro por recurso: %d", len(r.list()))
	}
	now := time.Now().UTC()
	if r := admin.do("GET", "/api/v1/audit-logs?from="+ts(now.Add(time.Hour)), nil); len(r.list()) != 0 {
		t.Error("período futuro")
	}
	for _, q := range []string{"actor_user_id=x", "from=ontem", "per_page=0"} {
		if r := admin.do("GET", "/api/v1/audit-logs?"+q, nil); r.Status != 422 {
			t.Errorf("%s: %d", q, r.Status)
		}
	}
	if r := admin.do("GET", "/api/v1/audit-logs?per_page=2&page=1", nil); len(r.list()) != 2 || r.meta()["total"].(float64) < 8 {
		t.Errorf("paginação: %s", r.Raw)
	}

	// NADA sensível na trilha: senhas (nova, antiga, digitada), hashes, tokens de sessão/CSRF/agente
	rows, _ := e.pool.Query(context.Background(), `SELECT metadata::text FROM audit_logs`)
	defer rows.Close()
	forbidden := []string{strongPw, "barco-de-papel", "girassol-veloz", "Senha-Digitada", "argon2", "ses_", admin.csrf, op.csrf, "snt_", adminKey, "password_hash"}
	n := 0
	for rows.Next() {
		var md string
		rows.Scan(&md)
		n++
		for _, f := range forbidden {
			if f != "" && strings.Contains(md, f) {
				t.Errorf("auditoria contém %q: %s", f, md)
			}
		}
	}
	if n < 8 {
		t.Errorf("registros: %d", n)
	}
	// só administradores leem a auditoria
	if r := op.do("GET", "/api/v1/audit-logs", nil); r.Status != 403 {
		t.Errorf("operador na auditoria: %d", r.Status)
	}
}
