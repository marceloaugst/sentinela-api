package http

import (
	"context"
	"io"
	"log/slog"
	nethttp "net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/config"
	"sentinela/internal/events"
	"sentinela/internal/telemetry"
)

var (
	pathRe   = regexp.MustCompile(`^  (/[^:\s]*):\s*$`)
	methodRe = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
)

// documentedRoutes extrai "MÉTODO /caminho" de api/openapi.yaml sem depender de biblioteca YAML.
func documentedRoutes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	cur := ""
	inPaths := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if inPaths && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			break // próxima seção de topo (components)
		}
		if m := pathRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
		} else if m := methodRe.FindStringSubmatch(line); m != nil && cur != "" {
			out[strings.ToUpper(m[1])+" "+cur] = true
		}
	}
	return out
}

// Garante que cada endpoint documentado existe no router e vice-versa.
func TestOpenAPIMatchesRouter(t *testing.T) {
	// pool lazy: não conecta até o primeiro uso
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/x?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reg := &Registry{}
	h := NewRouter(Deps{
		Registry: reg,
		Config:   config.Config{MaxBodyBytes: 1, RequestTimeout: 1, AgentHeartbeatTimeout: 60e9, AgentCollectInterval: 15e9},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:  telemetry.NewMetrics(),
		DB:       pool, Pool: pool,
		Hub: events.NewHub("", pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
	})
	routes := map[string]bool{}
	err = chi.Walk(h.(chi.Routes), func(method, route string, _ nethttp.Handler, _ ...func(nethttp.Handler) nethttp.Handler) error {
		routes[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	docs := documentedRoutes(t)
	if len(docs) == 0 {
		t.Fatal("nenhuma rota encontrada no openapi.yaml")
	}
	var missingDoc, missingImpl []string
	for r := range routes {
		if !docs[r] {
			missingDoc = append(missingDoc, r)
		}
	}
	for r := range docs {
		if !routes[r] {
			missingImpl = append(missingImpl, r)
		}
	}
	sort.Strings(missingDoc)
	sort.Strings(missingImpl)
	if len(missingDoc) > 0 {
		t.Errorf("rotas implementadas e não documentadas: %v", missingDoc)
	}
	if len(missingImpl) > 0 {
		t.Errorf("rotas documentadas e não implementadas: %v", missingImpl)
	}
}

// O teste acima compara só método+caminho (por regex). Este garante que o arquivo é YAML bem formado
// de verdade — um escalar com ": " sem aspas já quebrou o documento sem ninguém perceber.
func TestOpenAPIIsWellFormedYAML(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		// escalar simples (sem aspas/chaves) com ": " no valor de description/summary é inválido em YAML
		for _, key := range []string{"description: ", "summary: "} {
			if strings.HasPrefix(trimmed, key) {
				val := strings.TrimPrefix(trimmed, key)
				if val == "" || val[0] == '"' || val[0] == '\'' || val[0] == '|' || val[0] == '>' || val[0] == '{' || val[0] == '[' {
					continue
				}
				if strings.Contains(val, ": ") || strings.HasSuffix(val, ":") || strings.Contains(val, " #") {
					t.Errorf("openapi.yaml:%d: valor sem aspas contém \": \" (YAML inválido): %s", i+1, trimmed)
				}
			}
		}
		if strings.Contains(line, "\t") {
			t.Errorf("openapi.yaml:%d: tabulação não é permitida em YAML", i+1)
		}
	}
}

// documentedRoles lê o `x-required-role` de cada operação do OpenAPI.
func documentedRoles(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	roleRe := regexp.MustCompile(`^      x-required-role:\s*(\w+)\s*$`)
	cur, key := "", ""
	inPaths := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if inPaths && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			break
		}
		if m := pathRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
		} else if m := methodRe.FindStringSubmatch(line); m != nil && cur != "" {
			key = strings.ToUpper(m[1]) + " " + cur
			out[key] = ""
		} else if m := roleRe.FindStringSubmatch(line); m != nil && key != "" {
			out[key] = m[1]
		}
	}
	return out
}

// O papel que a documentação promete tem que ser o que o roteador realmente exige.
func TestOpenAPIRequiredRolesMatchTheRouter(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/x?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	reg := &Registry{}
	NewRouter(Deps{
		Registry: reg,
		Config:   config.Config{MaxBodyBytes: 1, RequestTimeout: 1, AgentHeartbeatTimeout: 60e9, AgentCollectInterval: 15e9, APIRateLimit: 1, APIRateBurst: 1},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: telemetry.NewMetrics(), DB: pool, Pool: pool,
		Hub: events.NewHub("", pool, slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
	})
	docs := documentedRoles(t)
	n := 0
	for _, rt := range reg.Routes {
		key := rt.Method + " " + rt.Path
		got, documented := docs[key]
		if !documented {
			t.Errorf("%s não está documentada", key)
			continue
		}
		want := string(rt.Role)
		if rt.Kind != "user" {
			want = "" // login (pública) e agentes (token próprio) não têm papel de usuário
		}
		if got != want {
			t.Errorf("%s: x-required-role = %q no OpenAPI, mas o roteador exige %q", key, got, want)
		}
		n++
	}
	if n < 50 {
		t.Errorf("apenas %d rotas comparadas", n)
	}
}
