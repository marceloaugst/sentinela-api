//go:build integration

package database_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/database"
	"sentinela/internal/testutil"
	"sentinela/migrations"
)

// env cria um schema isolado e vazio (sem migrações aplicadas).
func env(t *testing.T) (*database.Migrator, *pgxpool.Pool, func(string) int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	pool, err := database.NewPool(ctx, testutil.IsolatedURL(t), 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	m, err := database.NewMigrator(pool, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		var n int
		if err := pool.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	return m, pool, count
}

const tablesQ = `SELECT count(*) FROM information_schema.tables
	WHERE table_schema = current_schema() AND table_name <> 'schema_migrations'`

func TestMigrationsUpIdempotentDown(t *testing.T) {
	m, _, count := env(t)
	ctx := context.Background()

	n, err := m.Up(ctx)
	if err != nil || n != 11 {
		t.Fatalf("up: n=%d err=%v", n, err)
	}
	if got := count(tablesQ); got != 18 {
		t.Errorf("tabelas após up: %d", got)
	}
	n, err = m.Up(ctx)
	if err != nil || n != 0 {
		t.Errorf("segundo up deveria ser no-op: n=%d err=%v", n, err)
	}
	if v, _ := m.Version(ctx); v != 11 {
		t.Errorf("versão %d", v)
	}
	if n, err := m.Down(ctx, 0); err != nil || n != 11 {
		t.Fatalf("down: n=%d err=%v", n, err)
	}
	if got := count(tablesQ); got != 0 {
		t.Errorf("tabelas após down: %d", got)
	}
}

func TestMigrationsConcurrentUp(t *testing.T) {
	m, _, count := env(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Up(ctx)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("up concorrente: %v", err)
		}
	}
	if got := count("SELECT count(*) FROM schema_migrations"); got != 11 {
		t.Errorf("registros em schema_migrations: %d", got)
	}
}

func TestSchemaConstraints(t *testing.T) {
	m, pool, _ := env(t)
	ctx := context.Background()
	if _, err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var serverID, ruleID string
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO servers (name, hostname) VALUES ('web-1','web-1.local') RETURNING id`).Scan(&serverID))
	// nome único (case-insensitive) entre servidores não removidos
	if _, err := pool.Exec(ctx, `INSERT INTO servers (name, hostname) VALUES ('WEB-1','x')`); err == nil {
		t.Error("nome duplicado deveria falhar")
	}
	must(pool.QueryRow(ctx, `INSERT INTO alert_rules (name, metric_name, operator, threshold, severity)
		VALUES ('cpu','cpu_usage_percent','>',90,'critical') RETURNING id`).Scan(&ruleID))
	ins := `INSERT INTO alerts (rule_id, server_id, severity, message) VALUES ($1,$2,'critical','m')`
	_, err := pool.Exec(ctx, ins, ruleID, serverID)
	must(err)
	if _, err := pool.Exec(ctx, ins, ruleID, serverID); err == nil {
		t.Error("deduplicação: segundo alerta ativo deveria falhar")
	}
	_, err = pool.Exec(ctx, `UPDATE alerts SET status='resolved', resolved_at=now()`)
	must(err)
	if _, err := pool.Exec(ctx, ins, ruleID, serverID); err != nil {
		t.Errorf("após resolver, novo alerta deveria ser permitido: %v", err)
	}
	// replay da mesma amostra é rejeitado
	met := `INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		VALUES ($1, '2026-01-01T00:00:00Z', 10, 100, 50, 50)`
	_, err = pool.Exec(ctx, met, serverID)
	must(err)
	if _, err := pool.Exec(ctx, met, serverID); err == nil {
		t.Error("amostra duplicada deveria falhar")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		VALUES ($1, now(), 150, 1, 1, 1)`, serverID); err == nil {
		t.Error("cpu > 100 deveria falhar")
	}
}
