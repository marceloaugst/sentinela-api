//go:build integration

package events_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/events"
	"sentinela/internal/testutil"
)

var ctx = context.Background()
var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func startHub(t *testing.T, pool *pgxpool.Pool, url string) *events.Hub {
	t.Helper()
	h := events.NewHub(url, pool, quiet, nil)
	h.PollInterval = 10 * time.Second
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { h.Run(c); close(done) }()
	t.Cleanup(func() { cancel(); <-done; h.Close() })
	select {
	case <-h.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("hub não ficou pronto")
	}
	return h
}

func publish(t *testing.T, pool *pgxpool.Pool, typ, server string, data any) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := events.Publish(ctx, tx, typ, server, data); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, s *events.Sub, d time.Duration) events.Event {
	t.Helper()
	select {
	case e, ok := <-s.C:
		if !ok {
			t.Fatalf("assinatura encerrada (%s)", s.Reason())
		}
		return e
	case <-time.After(d):
		t.Fatal("evento não chegou a tempo")
	}
	return events.Event{}
}

func none(t *testing.T, s *events.Sub, d time.Duration) {
	t.Helper()
	select {
	case e := <-s.C:
		t.Fatalf("evento inesperado: %+v", e)
	case <-time.After(d):
	}
}

func count(t *testing.T, pool *pgxpool.Pool, q string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPublishIsAtomicWithTheTransaction(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	h := startHub(t, pool, url)
	sub, _ := h.Subscribe("ip", events.Filter{})

	tx, _ := pool.Begin(ctx)
	if err := events.Publish(ctx, tx, events.TypeAlertTriggered, "", map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}
	none(t, sub, 300*time.Millisecond) // ainda não confirmou: ninguém vê
	tx.Rollback(ctx)
	none(t, sub, 300*time.Millisecond)
	if count(t, pool, `SELECT count(*) FROM events`) != 0 {
		t.Error("rollback não pode deixar evento")
	}

	publish(t, pool, events.TypeAlertTriggered, "", map[string]any{"x": 2})
	e := recv(t, sub, 3*time.Second)
	// o rollback consumiu um id da sequência (normal): o importante é que só o confirmado aparece
	if e.ID < 1 || e.Type != events.TypeAlertTriggered || !jsonEq(e.Data, `{"x":2}`) || !e.Durable() {
		t.Errorf("%+v", e)
	}
	none(t, sub, 200*time.Millisecond)
}

// Caso difícil do padrão outbox: com ids de uma sequência, uma transação lenta poderia confirmar DEPOIS
// de outra com id maior e um cursor por id pularia o evento. A publicação serializada garante que os ids
// seguem a ordem de commit.
func TestEventIDsFollowCommitOrderUnderConcurrency(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	h := startHub(t, pool, url)
	sub, _ := h.Subscribe("ip", events.Filter{})

	const workers = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	committed := map[string]bool{}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer tx.Rollback(ctx)
			time.Sleep(time.Duration(rand.IntN(30)) * time.Millisecond)
			name := fmt.Sprintf("w%d", i)
			if err := events.Publish(ctx, tx, events.TypeAlertTriggered, "", map[string]string{"w": name}); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(time.Duration(rand.IntN(40)) * time.Millisecond) // commit demorado
			if i%5 == 0 {
				return // rollback: o evento não pode aparecer
			}
			if err := tx.Commit(ctx); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			committed[name] = true
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	var got []events.Event
	for len(got) < len(committed) {
		got = append(got, recv(t, sub, 5*time.Second))
	}
	none(t, sub, 300*time.Millisecond)
	if len(committed) != workers-workers/5 {
		t.Fatalf("premissa: %d commits", len(committed))
	}
	seen := map[string]bool{}
	var last int64
	for _, e := range got {
		if e.ID <= last {
			t.Fatalf("ids fora de ordem: %d depois de %d", e.ID, last)
		}
		last = e.ID
		var d map[string]string
		json.Unmarshal(e.Data, &d)
		if !committed[d["w"]] || seen[d["w"]] {
			t.Errorf("evento inesperado ou duplicado: %v", d)
		}
		seen[d["w"]] = true
	}
	// ids consecutivos na ordem de commit: nenhum evento confirmado ficou para trás do cursor
	ids := make([]int, 0, len(got))
	for _, e := range got {
		ids = append(ids, int(e.ID))
	}
	if !sort.IntsAreSorted(ids) {
		t.Error("ids deveriam estar ordenados")
	}
	if count(t, pool, `SELECT count(*) FROM events`) != len(committed) {
		t.Error("o log deve conter exatamente os eventos confirmados")
	}
}

func TestEveryInstanceDeliversEachEventExactlyOnce(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	hubA, hubB := startHub(t, pool, url), startHub(t, pool, url) // "duas instâncias da API"
	a, _ := hubA.Subscribe("ip", events.Filter{})
	b, _ := hubB.Subscribe("ip", events.Filter{})
	for i := 0; i < 5; i++ {
		publish(t, pool, events.TypeIncidentCreated, "", map[string]int{"i": i})
	}
	for i := 0; i < 5; i++ {
		ea, eb := recv(t, a, 3*time.Second), recv(t, b, 3*time.Second)
		if ea.ID != eb.ID || ea.ID != int64(i+1) {
			t.Errorf("i=%d A=%d B=%d", i, ea.ID, eb.ID)
		}
	}
	none(t, a, 200*time.Millisecond)
	none(t, b, 200*time.Millisecond)
}

func TestHubReconnectsAndCatchesUpOnEventsPublishedWhileDisconnected(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	h := startHub(t, pool, url)
	sub, _ := h.Subscribe("ip", events.Filter{})
	publish(t, pool, events.TypeAlertTriggered, "", map[string]int{"n": 1})
	recv(t, sub, 3*time.Second)

	// derruba a conexão de LISTEN e publica logo em seguida (o NOTIFY se perde)
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'sentinela-events'`); err != nil {
		t.Fatal(err)
	}
	publish(t, pool, events.TypeAlertTriggered, "", map[string]int{"n": 2})
	e := recv(t, sub, 8*time.Second) // reconexão (backoff de 1 s) + pull de recuperação
	if e.ID != 2 {
		t.Errorf("deveria recuperar o evento 2: %+v", e)
	}
	// e continua funcionando ao vivo depois de reconectar
	publish(t, pool, events.TypeAlertTriggered, "", map[string]int{"n": 3})
	if e := recv(t, sub, 5*time.Second); e.ID != 3 {
		t.Errorf("%+v", e)
	}
	none(t, sub, 300*time.Millisecond)
}

func TestPollingRecoversAMissedNotify(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	h := events.NewHub(url, pool, quiet, nil)
	h.PollInterval = 200 * time.Millisecond
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	go h.Run(c)
	<-h.Ready()
	sub, _ := h.Subscribe("ip", events.Filter{})
	// grava no log SEM NOTIFY (simula um NOTIFY perdido)
	if _, err := pool.Exec(ctx, `INSERT INTO events (type, data) VALUES ('alert.resolved', '{"k":1}')`); err != nil {
		t.Fatal(err)
	}
	if e := recv(t, sub, 3*time.Second); e.Type != events.TypeAlertResolved {
		t.Errorf("%+v", e)
	}
}

func TestLiveEventsArePassedThroughButNeverPersisted(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	h := startHub(t, pool, url)
	metrics, _ := h.Subscribe("ip", events.Filter{Types: map[string]bool{events.TypeMetricsUpdated: true}})
	def, _ := h.Subscribe("ip", events.Filter{})
	if err := events.PublishLive(ctx, pool, events.TypeMetricsUpdated, "srv-1", map[string]float64{"cpu": 12.5}); err != nil {
		t.Fatal(err)
	}
	e := recv(t, metrics, 3*time.Second)
	if e.Durable() || e.Type != events.TypeMetricsUpdated || e.ServerID != "srv-1" || string(e.Data) != `{"cpu":12.5}` {
		t.Errorf("%+v", e)
	}
	none(t, def, 300*time.Millisecond) // metrics.updated é opt-in
	if count(t, pool, `SELECT count(*) FROM events`) != 0 {
		t.Error("evento efêmero não pode ser gravado")
	}
	if err := events.PublishLive(ctx, pool, events.TypeMetricsUpdated, "", map[string]string{"x": string(make([]byte, 9000))}); err == nil {
		t.Error("payload acima do limite do NOTIFY deve ser recusado")
	}
}

func TestChannelsAreIsolatedPerSchema(t *testing.T) {
	poolA, urlA := testutil.NewDBURL(t)
	poolB, urlB := testutil.NewDBURL(t) // outro schema, MESMO banco
	hA, hB := startHub(t, poolA, urlA), startHub(t, poolB, urlB)
	a, _ := hA.Subscribe("ip", events.Filter{})
	b, _ := hB.Subscribe("ip", events.Filter{})
	publish(t, poolA, events.TypeAlertTriggered, "", map[string]string{"from": "A"})
	if e := recv(t, a, 3*time.Second); !jsonEq(e.Data, `{"from":"A"}`) {
		t.Errorf("%+v", e)
	}
	none(t, b, 500*time.Millisecond)
	events.PublishLive(ctx, poolB, events.TypeMetricsUpdated, "", map[string]string{"from": "B"})
	live, _ := hA.Subscribe("ip", events.Filter{Types: map[string]bool{events.TypeMetricsUpdated: true}})
	none(t, live, 500*time.Millisecond)
}

func TestReplayPositionAndPurge(t *testing.T) {
	pool, url := testutil.NewDBURL(t)
	h := startHub(t, pool, url)
	for i := 1; i <= 6; i++ {
		publish(t, pool, events.TypeAlertTriggered, "", map[string]int{"i": i})
	}
	evs, err := h.Replay(ctx, 3, 100)
	if err != nil || len(evs) != 3 || evs[0].ID != 4 || evs[2].ID != 6 {
		t.Fatalf("replay: %+v %v", evs, err)
	}
	if evs, _ := h.Replay(ctx, 0, 2); len(evs) != 2 {
		t.Errorf("limite: %d", len(evs))
	}
	maxID, purged, err := h.Position(ctx)
	if err != nil || maxID != 6 || purged != 0 {
		t.Fatalf("posição: %d %d %v", maxID, purged, err)
	}
	// os 4 primeiros ficam antigos; a retenção remove e registra o maior id removido
	pool.Exec(ctx, `UPDATE events SET created_at = now() - interval '2 days' WHERE id <= 4`)
	n, err := events.Purge(ctx, pool, time.Now().Add(-24*time.Hour))
	if err != nil || n != 4 {
		t.Fatalf("purge: %d %v", n, err)
	}
	maxID, purged, _ = h.Position(ctx)
	if maxID != 6 || purged != 4 {
		t.Errorf("posição após purge: max=%d purged=%d", maxID, purged)
	}
	if n, _ := events.Purge(ctx, pool, time.Now().Add(-24*time.Hour)); n != 0 {
		t.Errorf("segundo purge: %d", n)
	}
	if _, p2, _ := h.Position(ctx); p2 != 4 {
		t.Errorf("purged_until não pode regredir: %d", p2)
	}
}

// jsonEq compara JSON ignorando formatação (o jsonb do PostgreSQL normaliza espaços e ordem das chaves).
func jsonEq(got json.RawMessage, want string) bool {
	var a, b any
	return json.Unmarshal(got, &a) == nil && json.Unmarshal([]byte(want), &b) == nil && fmt.Sprint(a) == fmt.Sprint(b)
}
