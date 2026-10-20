//go:build integration

package retention_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"sentinela/internal/retention"
	"sentinela/internal/telemetry"
	"sentinela/internal/testutil"
)

func setup(t *testing.T) (*retention.Job, func(string, ...any) int, func(string, ...any)) {
	t.Helper()
	pool := testutil.NewDB(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		var n int
		if err := pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec(`INSERT INTO servers (id, name, hostname) VALUES ('11111111-1111-1111-1111-111111111111', 's', 'h')`)
	// 7 amostras com 40 dias (devem sair) e 3 recentes (devem ficar)
	exec(`INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		SELECT '11111111-1111-1111-1111-111111111111', now() - interval '40 days' + g * interval '1 minute', 1, 10, 5, 5
		FROM generate_series(1, 7) g`)
	exec(`INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		SELECT '11111111-1111-1111-1111-111111111111', now() - g * interval '1 minute', 1, 10, 5, 5
		FROM generate_series(1, 3) g`)
	job := &retention.Job{
		Pool: pool, Days: 30, Interval: time.Hour, Batch: 3,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: telemetry.NewMetrics(),
	}
	return job, count, exec
}

func TestRetentionDeletesOnlyOldRowsInBatches(t *testing.T) {
	job, count, _ := setup(t)
	// lote 3 com 7 linhas antigas => 3 iterações (3 + 3 + 1)
	n, err := job.RunOnce(context.Background())
	if err != nil || n != 7 {
		t.Fatalf("removidas: %d err=%v", n, err)
	}
	if got := count(`SELECT count(*) FROM server_metrics`); got != 3 {
		t.Errorf("restaram %d linhas (esperado 3 recentes)", got)
	}
	// idempotente
	if n, err := job.RunOnce(context.Background()); err != nil || n != 0 {
		t.Errorf("segunda execução: %d %v", n, err)
	}
}

func TestRetentionRespectsConfiguredDays(t *testing.T) {
	job, count, _ := setup(t)
	job.Days = 60 // nada com 40 dias deve ser removido
	if n, err := job.RunOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := count(`SELECT count(*) FROM server_metrics`); got != 10 {
		t.Errorf("linhas: %d", got)
	}
}

func TestRetentionSkipsWhenAnotherInstanceHoldsLock(t *testing.T) {
	job, count, _ := setup(t)
	ctx := context.Background()
	holder, err := job.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	if err := holder.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(0x53454e52)).Scan(&got); err != nil || !got {
		t.Fatalf("não obteve o lock: %v %v", got, err)
	}
	n, err := job.RunOnce(ctx)
	if err != nil || n != 0 || count(`SELECT count(*) FROM server_metrics`) != 10 {
		t.Errorf("com lock ocupado deveria pular: n=%d err=%v", n, err)
	}
	_, _ = holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", int64(0x53454e52))
	holder.Release()

	if n, err := job.RunOnce(ctx); err != nil || n != 7 {
		t.Errorf("após liberar o lock: n=%d err=%v", n, err)
	}
}

func TestRetentionConcurrentRunsDoNotConflict(t *testing.T) {
	job, count, _ := setup(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := job.RunOnce(context.Background())
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 7 || count(`SELECT count(*) FROM server_metrics`) != 3 {
		t.Errorf("total removido %d (esperado exatamente 7)", total)
	}
}

func TestRetentionStopsOnContextCancel(t *testing.T) {
	job, _, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { job.Run(ctx); close(done) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run não encerrou após cancelar o contexto")
	}
}
