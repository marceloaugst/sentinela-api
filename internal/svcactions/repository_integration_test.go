//go:build integration

package svcactions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/svcactions"
	"sentinela/internal/testutil"
)

const (
	srv   = "11111111-1111-1111-1111-111111111111"
	other = "22222222-2222-2222-2222-222222222222"
	user  = "33333333-3333-3333-3333-333333333333"
)

func setup(t *testing.T) (*svcactions.Repository, *pgxpool.Pool, context.Context) {
	pool := testutil.NewDB(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO servers (id, name, hostname) VALUES ('` + srv + `', 's', 'h'), ('` + other + `', 'o', 'h2')`,
		`INSERT INTO users (id, email, name, password_hash, role) VALUES ('` + user + `', 'op@x.com', 'Op', 'x', 'operator')`,
		`INSERT INTO service_discovery (server_id, key, status, source, unit, checked_at) VALUES
			('` + srv + `', 'nginx', 'available', 'systemd', 'nginx.service', now()),
			('` + srv + `', 'cron', 'stopped', '', 'cron.service', now()),
			('` + srv + `', 'redis', 'available', 'docker', '', now()),
			('` + srv + `', 'ssh', 'available', 'systemd', 'ssh.service', now())`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return svcactions.NewRepository(pool), pool, ctx
}

func counter(t *testing.T, pool *pgxpool.Pool) func(string) int {
	return func(q string) int {
		var n int
		if err := pool.QueryRow(context.Background(), q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
}

// age empurra um carimbo de tempo do comando para o passado, para provar os prazos.
func age(t *testing.T, pool *pgxpool.Pool, id, col string, by time.Duration) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `UPDATE service_commands SET `+col+` = now() - make_interval(secs => $2) WHERE id = $1`,
		id, by.Seconds()); err != nil {
		t.Fatal(err)
	}
}

func TestRequestClaimComplete(t *testing.T) {
	repo, pool, ctx := setup(t)
	count := counter(t, pool)
	ac := audit.Context{Actor: "op@x.com", UserID: user, IP: "203.0.113.9"}

	cmd, err := repo.Request(ctx, ac, srv, "nginx", "restart")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != svcactions.StatusPending || cmd.Unit != "nginx.service" || cmd.RequestedBy == nil || *cmd.RequestedBy != user || cmd.Actor != "op@x.com" {
		t.Fatalf("comando inesperado: %+v", cmd)
	}
	// Quem deu o comando fica na auditoria, com usuário e IP.
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'service.restart' AND resource_type = 'server'
		AND resource_id = '` + srv + `' AND actor_user_id = '` + user + `' AND ip = '203.0.113.9'
		AND metadata->>'service' = 'nginx' AND metadata->>'actor' = 'op@x.com'`); n != 1 {
		t.Fatalf("auditoria do pedido: %d linhas", n)
	}

	// Segundo pedido enquanto o primeiro está ativo.
	if _, err := repo.Request(ctx, ac, srv, "nginx", "stop"); !errors.Is(err, svcactions.ErrBusy) {
		t.Fatalf("esperado ErrBusy, veio %v", err)
	}
	// Outro servidor não enxerga o comando.
	if got, err := repo.Claim(ctx, other); err != nil || len(got) != 0 {
		t.Fatalf("outro servidor recebeu comandos: %v %v", got, err)
	}
	got, err := repo.Claim(ctx, srv)
	if err != nil || len(got) != 1 || got[0].ID != cmd.ID || got[0].ServiceKey != "nginx" || got[0].Action != "restart" {
		t.Fatalf("claim: %v %v", got, err)
	}
	if again, _ := repo.Claim(ctx, srv); len(again) != 0 {
		t.Fatal("o mesmo comando foi entregue duas vezes")
	}
	// O resultado só vale para o servidor dono.
	if err := repo.Complete(ctx, other, cmd.ID, svcactions.Result{Status: svcactions.StatusSucceeded}); !errors.Is(err, svcactions.ErrNotFound) {
		t.Fatalf("outro servidor concluiu o comando: %v", err)
	}
	if err := repo.Complete(ctx, srv, cmd.ID, svcactions.Result{Status: svcactions.StatusSucceeded, Message: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Complete(ctx, srv, cmd.ID, svcactions.Result{Status: svcactions.StatusFailed}); !errors.Is(err, svcactions.ErrInvalidState) {
		t.Fatalf("resultado duplicado: %v", err)
	}
	c, err := repo.Get(ctx, cmd.ID)
	if err != nil || c.Status != svcactions.StatusSucceeded || c.Message != "ok" || c.FinishedAt == nil {
		t.Fatalf("estado final: %+v %v", c, err)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'service.result' AND metadata->>'result' = 'succeeded'`); n != 1 {
		t.Fatalf("auditoria do resultado: %d", n)
	}
	// Liberado: pode pedir de novo.
	if _, err := repo.Request(ctx, ac, srv, "nginx", "stop"); err != nil {
		t.Fatal(err)
	}
	if list, err := repo.List(ctx, srv, 10); err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
}

func TestRequestRules(t *testing.T) {
	repo, pool, ctx := setup(t)
	count := counter(t, pool)
	ac := audit.Context{Actor: "op@x.com", UserID: user}
	for _, c := range []struct {
		key, action string
		want        error
	}{
		{"nginx", "start", svcactions.ErrNotActionable}, // já está rodando
		{"cron", "stop", svcactions.ErrNotActionable},   // já está parado
		{"cron", "restart", svcactions.ErrNotActionable},
		{"redis", "restart", svcactions.ErrNotActionable}, // container
		{"ssh", "stop", svcactions.ErrNotActionable},      // trancaria o administrador fora
		{"postgresql", "stop", svcactions.ErrNoDiscovery}, // nunca descoberto
	} {
		if _, err := repo.Request(ctx, ac, srv, c.key, c.action); !errors.Is(err, c.want) {
			t.Errorf("%s %s: %v, esperado %v", c.key, c.action, err, c.want)
		}
	}
	if _, err := repo.Request(ctx, ac, srv, "cron", "start"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Request(ctx, ac, srv, "ssh", "restart"); err != nil {
		t.Fatal(err)
	}
	// Pedidos recusados não deixam auditoria nem comando.
	if n := count(`SELECT count(*) FROM service_commands`); n != 2 {
		t.Fatalf("comandos gravados: %d", n)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action LIKE 'service.%'`); n != 2 {
		t.Fatalf("auditorias: %d", n)
	}
}

func TestExpiry(t *testing.T) {
	repo, pool, ctx := setup(t)
	cmd, err := repo.Request(ctx, audit.Context{Actor: "api_key"}, srv, "nginx", "stop")
	if err != nil {
		t.Fatal(err)
	}
	age(t, pool, cmd.ID, "created_at", svcactions.PendingTTL+time.Second)
	if c, err := repo.Get(ctx, cmd.ID); err != nil || c.Status != svcactions.StatusExpired {
		t.Fatalf("pendente antigo deveria expirar: %+v %v", c, err)
	}
	if got, _ := repo.Claim(ctx, srv); len(got) != 0 {
		t.Fatal("comando expirado foi entregue ao agente")
	}
	// Em execução sem resultado vira falha.
	c2, err := repo.Request(ctx, audit.Context{Actor: "api_key"}, srv, "nginx", "restart")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Claim(ctx, srv); len(got) != 1 {
		t.Fatal("claim")
	}
	age(t, pool, c2.ID, "started_at", svcactions.RunningTTL+time.Second)
	if c, err := repo.Get(ctx, c2.ID); err != nil || c.Status != svcactions.StatusFailed {
		t.Fatalf("em execução antigo deveria falhar: %+v %v", c, err)
	}
}
