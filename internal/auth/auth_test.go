package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRoleOrdering(t *testing.T) {
	cases := []struct {
		have, need Role
		want       bool
	}{
		{Admin, Admin, true}, {Admin, Operator, true}, {Admin, Viewer, true},
		{Operator, Admin, false}, {Operator, Operator, true}, {Operator, Viewer, true},
		{Viewer, Admin, false}, {Viewer, Operator, false}, {Viewer, Viewer, true},
		{"", Viewer, false}, {"root", Viewer, false}, {"ADMIN", Viewer, false}, // papel desconhecido nunca passa
	}
	for _, c := range cases {
		if c.have.AtLeast(c.need) != c.want {
			t.Errorf("%q.AtLeast(%q) = %v", c.have, c.need, !c.want)
		}
	}
	if (Principal{Via: ViaAPIKey}).Actor() != "api_key" || (Principal{Via: ViaSession, Email: "a@b.com"}).Actor() != "a@b.com" {
		t.Error("Actor")
	}
}

func TestSessionTokenFormatAndCSRF(t *testing.T) {
	a, _ := newToken()
	b, _ := newToken()
	if a == b || !validTokenFormat(a) || len(a) != 68 {
		t.Errorf("token: %q", a)
	}
	for _, bad := range []string{"", a[4:], strings.ToUpper(a), a + "00", "ses_" + strings.Repeat("g", 64), "snt_" + a[4:], a[:67]} {
		if validTokenFormat(bad) {
			t.Errorf("%q não deveria ser válido", bad)
		}
	}
	if len(hashToken(a)) != 32 || string(hashToken(a)) == a {
		t.Error("hash")
	}
	c1, c2 := CSRFToken(a), CSRFToken(b)
	if c1 == c2 || c1 != CSRFToken(a) || strings.Contains(c1, a[4:20]) {
		t.Error("CSRF deve ser determinístico por sessão, distinto entre sessões e não conter o token")
	}
	if !csrfEqual(c1, CSRFToken(a)) || csrfEqual(c1, c2) || csrfEqual(c1, "") || csrfEqual("", "") && false {
		t.Error("csrfEqual")
	}
}

func TestCookieAttributes(t *testing.T) {
	sess := Session{Token: "ses_" + strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}
	for _, secure := range []bool{true, false} {
		s := &Service{cfg: Config{CookieSecure: secure}.withDefaults()}
		rec := httptest.NewRecorder()
		s.SetCookie(rec, sess)
		c := rec.Result().Cookies()[0]
		wantName := "sentinela_session"
		if secure {
			wantName = "__Host-sentinela_session" // prefixo exige Secure, Path=/ e sem Domain
		}
		if c.Name != wantName || !c.HttpOnly || c.Secure != secure || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 {
			t.Errorf("secure=%v: %+v", secure, c)
		}
		rec = httptest.NewRecorder()
		s.ClearCookie(rec)
		if c := rec.Result().Cookies()[0]; c.Value != "" || c.MaxAge >= 0 || !c.HttpOnly || c.Secure != secure {
			t.Errorf("limpar: %+v", c)
		}
	}
	s := &Service{cfg: Config{CookieSecure: true, SameSite: http.SameSiteStrictMode}.withDefaults()}
	rec := httptest.NewRecorder()
	s.SetCookie(rec, sess)
	if rec.Result().Cookies()[0].SameSite != http.SameSiteStrictMode {
		t.Error("SameSite configurável")
	}
}

func TestAPIKeyAndOrigin(t *testing.T) {
	s := &Service{cfg: Config{APIKey: strings.Repeat("k", 40), AllowedOrigins: []string{"https://painel.exemplo.com"}}.withDefaults()}
	if !s.apiKeyMatches(strings.Repeat("k", 40)) || s.apiKeyMatches(strings.Repeat("k", 39)) || s.apiKeyMatches("") {
		t.Error("apiKeyMatches")
	}
	if (&Service{cfg: Config{}.withDefaults()}).apiKeyMatches("") {
		t.Error("sem chave configurada, nada (nem vazio) autentica")
	}
	r := httptest.NewRequest("POST", "http://api.exemplo.com/x", nil)
	r.Host = "api.exemplo.com"
	for origin, want := range map[string]bool{
		"https://painel.exemplo.com": true, "https://api.exemplo.com": true, "http://API.exemplo.com": true,
		"https://evil.com": false, "null": false, "https://painel.exemplo.com.evil.com": false, "https://api.exemplo.com.evil.com": false, "": false,
	} {
		if got := s.originAllowed(r, origin); got != want {
			t.Errorf("origem %q: %v (esperado %v)", origin, got, want)
		}
	}
}

func TestRequireRole(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	run := func(p *Principal, need Role) int {
		req := httptest.NewRequest("GET", "/", nil)
		if p != nil {
			req = req.WithContext(WithPrincipal(req.Context(), *p))
		}
		rec := httptest.NewRecorder()
		Require(need)(ok).ServeHTTP(rec, req)
		return rec.Code
	}
	if run(nil, Viewer) != 401 {
		t.Error("sem principal => 401")
	}
	if run(&Principal{Role: Viewer}, Operator) != 403 || run(&Principal{Role: Operator}, Operator) != 204 || run(&Principal{Role: Admin}, Operator) != 204 || run(&Principal{Role: "x"}, Viewer) != 403 {
		t.Error("papéis")
	}
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.AbsoluteTTL != 24*time.Hour || c.IdleTTL != 2*time.Hour || c.MaxFailuresPair != 5 || c.MaxFailuresIP != 20 || c.MaxFailuresEmail != 30 || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("%+v", c)
	}
}
