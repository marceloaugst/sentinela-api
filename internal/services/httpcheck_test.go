package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinela/internal/ssrf"
)

func loopbackAllowed(t *testing.T) *Checker {
	t.Helper()
	pre, err := ssrf.ParseAllowed("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return NewChecker(ssrf.Policy{Allowed: pre})
}

func cfg(c Config) Config {
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 3
	}
	return c
}

func TestCheckUpDownAndCriteria(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"status":"healthy","db":"up"}`))
		case "/degraded":
			w.Write([]byte(`{"status":"healthy","db":"down"}`))
		case "/500":
			w.WriteHeader(500)
		case "/302":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/slow":
			time.Sleep(150 * time.Millisecond)
			w.Write([]byte("ok"))
		case "/hang":
			time.Sleep(3 * time.Second)
		}
	}))
	defer srv.Close()
	c := loopbackAllowed(t)
	ctx := context.Background()

	cases := []struct {
		name   string
		path   string
		cfg    Config
		status string
		code   int
	}{
		{"200 esperado", "/ok", Config{}, StatusUp, 200},
		{"500 inesperado", "/500", Config{}, StatusDown, 500},
		{"500 esperado por configuração", "/500", Config{ExpectedStatus: []int{500}}, StatusUp, 500},
		{"corpo contém texto", "/ok", Config{BodyContains: `"db":"up"`}, StatusUp, 200},
		{"200 mas app não saudável", "/degraded", Config{BodyContains: `"db":"up"`}, StatusDown, 200},
		{"HEAD", "/ok", Config{Method: "HEAD"}, StatusUp, 200},
		{"latência acima do limite", "/slow", Config{MaxLatencyMS: 50}, StatusDegraded, 200},
		{"latência dentro do limite", "/slow", Config{MaxLatencyMS: 2000}, StatusUp, 200},
		// redirecionamento NÃO é seguido: avaliado como 302 (e o destino interno jamais é contatado)
		{"redirect não seguido", "/302", Config{}, StatusDown, 302},
		{"redirect esperado", "/302", Config{ExpectedStatus: []int{302}}, StatusUp, 302},
	}
	for _, tc := range cases {
		r := c.Check(ctx, srv.URL+tc.path, cfg(tc.cfg))
		if r.Status != tc.status || r.StatusCode == nil || *r.StatusCode != tc.code {
			t.Errorf("%s: status=%s code=%v err=%q", tc.name, r.Status, r.StatusCode, r.Error)
		}
		if r.Status == StatusUp && r.Error != "" {
			t.Errorf("%s: up não deve ter erro", tc.name)
		}
	}
	r := c.Check(ctx, srv.URL+"/hang", Config{TimeoutSeconds: 1})
	if r.Status != StatusDown || r.Error != "tempo limite excedido" {
		t.Errorf("timeout: %+v", r)
	}
}

func TestCheckBlocksInternalTargetsByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("interno")) }))
	defer srv.Close()
	c := NewChecker(ssrf.Policy{}) // política padrão: nada interno
	for _, target := range []string{srv.URL, "http://localhost:1/", "http://169.254.169.254/", "http://[::1]:80/"} {
		r := c.Check(context.Background(), target, cfg(Config{}))
		if r.Status != StatusDown || r.StatusCode != nil || r.LatencyMS != nil {
			t.Errorf("%s: %+v", target, r)
		}
		if !strings.Contains(r.Error, "política") {
			t.Errorf("%s: erro deveria citar a política: %q", target, r.Error)
		}
		if strings.Contains(r.Error, "127.0.0.1") || strings.Contains(r.Error, "169.254") {
			t.Errorf("erro vaza endereço interno: %q", r.Error)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("o servidor interno recebeu %d requisições — SSRF!", hits.Load())
	}
}

func TestCheckBlocksAtConnectTimeEvenIfURLValidationPasses(t *testing.T) {
	// "localhost" falha na validação estática; para exercitar o bloqueio na CONEXÃO, valida com
	// política permissiva e conecta com a restritiva (simula DNS apontando para IP interno).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer srv.Close()
	permissive := ssrf.Policy{Allowed: mustAllowed(t, "127.0.0.0/8")}
	strict := NewChecker(ssrf.Policy{})
	strict.Policy = permissive // validação estática passa...
	// ...mas o transporte continua usando a política restritiva criada em NewChecker.
	r := strict.Check(context.Background(), srv.URL, cfg(Config{}))
	if r.Status != StatusDown || !strings.Contains(r.Error, "política") {
		t.Errorf("bloqueio na conexão: %+v", r)
	}
}

func mustAllowed(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := ssrf.ParseAllowed(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClassifyErrorsAreGeneric(t *testing.T) {
	c := loopbackAllowed(t)
	r := c.Check(context.Background(), "http://127.0.0.1:1/", cfg(Config{})) // porta fechada
	if r.Status != StatusDown || r.Error != "falha de conexão" {
		t.Errorf("%+v", r)
	}
	r = c.Check(context.Background(), "https://nao-existe.invalid/", cfg(Config{}))
	if r.Status != StatusDown || r.Error == "" {
		t.Errorf("%+v", r)
	}
}

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 404: "404", -12: "-12"} {
		if itoa(n) != want {
			t.Errorf("%d -> %s", n, itoa(n))
		}
	}
}
