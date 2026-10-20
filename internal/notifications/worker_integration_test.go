//go:build integration

package notifications_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"sentinela/internal/alerts"
	"sentinela/internal/audit"
	"sentinela/internal/notifications"
	"sentinela/internal/secrets"
	"sentinela/internal/telemetry"
	itestutil "sentinela/internal/testutil"
)

const (
	token = "123456789:AAH-testtoken_abcdefghijklmnopqrstuvwxyz1234"
	chat  = "-1001"
)

var ctx = context.Background()
var actor = audit.Context{Actor: "teste"}

type tgReq struct{ Token, Chat, Text string }

// fakeTG simula a Bot API; "script" define respostas programadas (vazio = 200 ok).
type fakeTG struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []tgReq
	script []func(http.ResponseWriter)
}

func newFakeTG(t *testing.T) *fakeTG {
	f := &fakeTG{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		tok := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/bot"), "/sendMessage")
		f.mu.Lock()
		f.reqs = append(f.reqs, tgReq{tok, fmt.Sprint(body["chat_id"]), fmt.Sprint(body["text"])})
		var step func(http.ResponseWriter)
		if len(f.script) > 0 {
			step, f.script = f.script[0], f.script[1:]
		}
		f.mu.Unlock()
		if step != nil {
			step(w)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTG) then(steps ...func(http.ResponseWriter)) {
	f.mu.Lock()
	f.script = append(f.script, steps...)
	f.mu.Unlock()
}
func (f *fakeTG) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }
func (f *fakeTG) texts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.reqs {
		out = append(out, r.Text)
	}
	return out
}

func status(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code); w.Write([]byte(body)) }
}

type env struct {
	t       *testing.T
	pool    *pgxpool.Pool
	box     *secrets.Box
	chans   *notifications.ChannelRepository
	tg      *fakeTG
	worker  *notifications.Worker
	metrics *telemetry.Metrics
}

func newEnv(t *testing.T) *env {
	pool := itestutil.NewDB(t)
	box, _ := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	chans := notifications.NewChannelRepository(pool, box, []string{chat})
	tg := newFakeTG(t)
	m := telemetry.NewMetrics()
	e := &env{t: t, pool: pool, box: box, chans: chans, tg: tg, metrics: m}
	e.worker = &notifications.Worker{
		Pool: pool, Box: box, Channels: chans, Sender: notifications.NewTelegram(tg.srv.URL),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: m,
		MaxAttempts: 8, Backoff: func(int) time.Duration { return 0 },
	}
	return e
}

func (e *env) channel(min string) notifications.Channel {
	e.t.Helper()
	in := notifications.CreateInput{Name: "ops-" + min, BotToken: token, ChatID: chat, MinSeverity: min}
	if p := in.Validate(); len(p) > 0 {
		e.t.Fatal(p)
	}
	c, err := e.chans.Create(ctx, actor, in)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *env) tick() {
	e.t.Helper()
	if err := e.worker.Tick(ctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) enqueue(p notifications.Payload) {
	e.t.Helper()
	tx, _ := e.pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if err := notifications.EnqueueAlert(ctx, tx, p); err != nil {
		e.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatal(err)
	}
}

func payload(id, sev, kind string) notifications.Payload {
	return notifications.Payload{Kind: kind, AlertID: id, ServerName: "web-1", RuleName: "CPU alta", Severity: sev,
		Message: "msg " + id, At: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

const (
	a1 = "11111111-1111-1111-1111-111111111111"
	a2 = "22222222-2222-2222-2222-222222222222"
)

func TestChannelTokenIsEncryptedAndNeverExposed(t *testing.T) {
	e := newEnv(t)
	c := e.channel("critical")
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "AAH-") || strings.Contains(string(raw), "bot_token") || !c.HasToken {
		t.Errorf("a resposta não pode conter o token: %s", raw)
	}
	var enc []byte
	e.pool.QueryRow(ctx, `SELECT secret_encrypted FROM notification_channels`).Scan(&enc)
	if len(enc) == 0 || bytes.Contains(enc, []byte("AAH-testtoken")) || bytes.Contains(enc, []byte("123456789")) {
		t.Error("o token não pode estar em texto puro no banco")
	}
	if plain, err := e.box.Decrypt(enc); err != nil || string(plain) != token {
		t.Errorf("decifrar: %v", err)
	}
	var cfg string
	e.pool.QueryRow(ctx, `SELECT config::text FROM notification_channels`).Scan(&cfg)
	if strings.Contains(cfg, "AAH-") {
		t.Error("o token não pode estar no config")
	}
	if e.count(`SELECT count(*) FROM audit_logs WHERE metadata::text LIKE '%AAH-%' OR metadata::text LIKE '%123456789%'`) != 0 {
		t.Error("token vazou para a auditoria")
	}
	if e.count(`SELECT count(*) FROM audit_logs WHERE action='notification_channel.create'`) != 1 {
		t.Error("criação do canal deveria ser auditada")
	}
	got, _ := e.chans.Get(ctx, c.ID)
	list, _ := e.chans.List(ctx)
	rawList, _ := json.Marshal(list)
	if got.ChatID != chat || len(list) != 1 || strings.Contains(string(rawList), "AAH-") {
		t.Errorf("get/list: %+v", got)
	}

	// troca de token: cifra de novo, sem expor
	newTok := "987654321:BBH-othertoken_abcdefghijklmnopqrstuvwxyz1234"
	if _, err := e.chans.Update(ctx, actor, c.ID, notifications.UpdateInput{BotToken: &newTok}); err != nil {
		t.Fatal(err)
	}
	var enc2 []byte
	e.pool.QueryRow(ctx, `SELECT secret_encrypted FROM notification_channels`).Scan(&enc2)
	if plain, _ := e.box.Decrypt(enc2); string(plain) != newTok || bytes.Equal(enc, enc2) {
		t.Error("token deveria ter sido recifrado")
	}
}

func TestChannelAuthorizationRules(t *testing.T) {
	e := newEnv(t)
	in := notifications.CreateInput{Name: "x", BotToken: token, ChatID: "999", MinSeverity: "critical"}
	if _, err := e.chans.Create(ctx, actor, in); err != notifications.ErrChatNotAllowed {
		t.Errorf("chat fora da lista: %v", err)
	}
	noKey := notifications.NewChannelRepository(e.pool, nil, []string{chat})
	in.ChatID = chat
	if _, err := noKey.Create(ctx, actor, in); err != notifications.ErrNoSecretsKey {
		t.Errorf("sem SECRETS_KEY: %v", err)
	}
	empty := notifications.NewChannelRepository(e.pool, e.box, nil)
	if _, err := empty.Create(ctx, actor, in); err != notifications.ErrChatNotAllowed {
		t.Errorf("sem destinos autorizados nada é permitido: %v", err)
	}
	c := e.channel("critical")
	other := "555"
	if _, err := e.chans.Update(ctx, actor, c.ID, notifications.UpdateInput{ChatID: &other}); err != notifications.ErrChatNotAllowed {
		t.Errorf("update para chat não autorizado: %v", err)
	}
	if err := e.chans.Delete(ctx, actor, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.chans.Get(ctx, c.ID); err != notifications.ErrChannelNotFound {
		t.Errorf("após excluir: %v", err)
	}
}

func TestUpsertFromEnvIsIdempotent(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 3; i++ {
		if err := e.chans.UpsertFromEnv(ctx, token, chat); err != nil {
			t.Fatal(err)
		}
	}
	if e.count(`SELECT count(*) FROM notification_channels WHERE name=$1`, notifications.EnvChannelName) != 1 {
		t.Error("deveria existir um único canal do ambiente")
	}
	if err := e.chans.UpsertFromEnv(ctx, "", ""); err != nil {
		t.Error("sem variáveis é no-op")
	}
	noKey := notifications.NewChannelRepository(e.pool, nil, nil)
	if err := noKey.UpsertFromEnv(ctx, token, chat); err != notifications.ErrNoSecretsKey {
		t.Errorf("token no ambiente sem SECRETS_KEY deve falhar: %v", err)
	}
	// o canal criado a partir do ambiente entrega mensagens
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e.tick()
	if e.tg.count() != 1 || e.tg.reqs[0].Token != token {
		t.Errorf("entrega pelo canal do ambiente: %+v", e.tg.reqs)
	}
}

func TestEnqueueRulesSeverityRecoveryAndDedup(t *testing.T) {
	e := newEnv(t)
	crit := e.channel("critical")
	warn := notifications.CreateInput{Name: "avisos", BotToken: token, ChatID: chat, MinSeverity: "warning"}
	warn.Validate()
	wch, _ := e.chans.Create(ctx, actor, warn)

	e.enqueue(payload(a1, "warning", notifications.KindTriggered))
	if e.count(`SELECT count(*) FROM notification_outbox WHERE channel_id=$1`, crit.ID) != 0 || e.count(`SELECT count(*) FROM notification_outbox WHERE channel_id=$1`, wch.ID) != 1 {
		t.Error("warning só vai ao canal com min_severity warning")
	}
	e.enqueue(payload(a2, "critical", notifications.KindTriggered))
	if e.count(`SELECT count(*) FROM notification_outbox`) != 3 {
		t.Error("critical vai aos dois canais")
	}
	// idempotência: a mesma transição enfileirada de novo não duplica
	e.enqueue(payload(a2, "critical", notifications.KindTriggered))
	if e.count(`SELECT count(*) FROM notification_outbox`) != 3 {
		t.Error("dedup_key deveria impedir duplicatas")
	}
	// recuperação só para quem recebeu o disparo
	e.enqueue(payload(a1, "warning", notifications.KindResolved))
	e.enqueue(payload("33333333-3333-3333-3333-333333333333", "critical", notifications.KindResolved)) // nunca notificado
	if e.count(`SELECT count(*) FROM notification_outbox WHERE dedup_key LIKE '%:resolved'`) != 1 {
		t.Errorf("recuperação sem disparo prévio não deve notificar: %d", e.count(`SELECT count(*) FROM notification_outbox WHERE dedup_key LIKE '%:resolved'`))
	}
	// canal desabilitado não recebe
	off := false
	e.chans.Update(ctx, actor, crit.ID, notifications.UpdateInput{IsEnabled: &off})
	e.enqueue(payload("44444444-4444-4444-4444-444444444444", "critical", notifications.KindTriggered))
	if e.count(`SELECT count(*) FROM notification_outbox WHERE channel_id=$1 AND dedup_key LIKE 'alert:4444%'`, crit.ID) != 0 {
		t.Error("canal desabilitado não deve receber")
	}
}

// Fluxo completo: avaliador → fila → Telegram, sem repetir mensagens enquanto a condição persiste.
func TestEndToEndNoRepeatedNotificationsWhileConditionPersists(t *testing.T) {
	e := newEnv(t)
	e.channel("critical")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	ev := &alerts.Evaluator{Pool: e.pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatTimeout: time.Minute, Now: func() time.Time { return now }}
	arepo := alerts.NewRepository(e.pool)

	var srv string
	e.pool.QueryRow(ctx, `INSERT INTO servers (name, hostname) VALUES ('web-1','h') RETURNING id`).Scan(&srv)
	beat := func(cpu float64) {
		e.pool.Exec(ctx, `INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes) VALUES ($1,$2,$3,10,5,5)`, srv, now, cpu)
		e.pool.Exec(ctx, `UPDATE servers SET last_seen_at=$2 WHERE id=$1`, srv, now)
	}
	arepo.CreateRule(ctx, actor, alerts.Rule{Name: "CPU alta", MetricName: alerts.MetricCPU, Operator: ">", Threshold: 90, Severity: "critical", IsEnabled: true})
	warnRule := alerts.Rule{Name: "CPU média", MetricName: alerts.MetricCPU, Operator: ">", Threshold: 50, Severity: "warning", IsEnabled: true}
	arepo.CreateRule(ctx, actor, warnRule)

	// 20 coletas consecutivas com a condição ativa
	for i := 0; i < 20; i++ {
		beat(95)
		if err := ev.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		e.tick()
		now = now.Add(15 * time.Second)
	}
	if e.tg.count() != 1 {
		t.Fatalf("esperava exatamente 1 mensagem (a regra de aviso não notifica o canal crítico): %d\n%v", e.tg.count(), e.tg.texts())
	}
	txt := e.tg.texts()[0]
	for _, want := range []string{"🔴", "CRÍTICO", "web-1", "CPU alta", "95.0%", "2026-03-01 12:00:00 UTC"} {
		if !strings.Contains(txt, want) {
			t.Errorf("mensagem sem %q:\n%s", want, txt)
		}
	}

	// recuperação: uma única mensagem
	for i := 0; i < 5; i++ {
		beat(10)
		ev.Tick(ctx)
		e.tick()
		now = now.Add(15 * time.Second)
	}
	if e.tg.count() != 2 || !strings.Contains(e.tg.texts()[1], "RECUPERADO") {
		t.Errorf("esperava 2 mensagens (disparo + recuperação): %v", e.tg.texts())
	}
	if e.count(`SELECT count(*) FROM notification_outbox WHERE status='sent'`) != 2 {
		t.Error("ambas deveriam constar como enviadas")
	}
	if testutil.ToFloat64(e.metrics.Notifications.WithLabelValues("sent")) != 2 {
		t.Error("métrica notifications_total{result=sent}")
	}
}

func TestRecoveryNotSentWhenChannelCreatedAfterTrigger(t *testing.T) {
	e := newEnv(t)
	e.enqueue(payload(a1, "critical", notifications.KindTriggered)) // sem canais: nada enfileirado
	e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindResolved))
	if e.count(`SELECT count(*) FROM notification_outbox`) != 0 {
		t.Error("recuperação sem aviso de disparo ao canal não deve ser enviada")
	}
}

func TestRetryWithBackoffThenSuccess(t *testing.T) {
	e := newEnv(t)
	e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e.tg.then(status(500, `{}`), status(502, ``))

	e.tick()
	e.tick()
	if e.count(`SELECT count(*) FROM notification_outbox WHERE status='pending' AND attempts=2 AND last_error IS NOT NULL`) != 1 {
		t.Fatal("após 2 falhas deveria estar pendente com 2 tentativas e erro registrado")
	}
	e.tick() // terceira tentativa: sucesso
	if e.tg.count() != 3 || e.count(`SELECT count(*) FROM notification_outbox WHERE status='sent' AND attempts=3 AND last_error IS NULL`) != 1 {
		t.Errorf("reqs=%d", e.tg.count())
	}
	e.tick()
	if e.tg.count() != 3 {
		t.Error("mensagem enviada não deve ser reenviada")
	}
	if testutil.ToFloat64(e.metrics.Notifications.WithLabelValues("retry")) != 2 {
		t.Error("métrica de retentativas")
	}
}

func TestPermanentFailureIsRecordedAndNotRetried(t *testing.T) {
	e := newEnv(t)
	e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e.tg.then(status(400, `{"ok":false,"description":"Bad Request: chat not found `+token+`"}`))
	e.tick()
	e.tick()
	e.tick()
	if e.tg.count() != 1 {
		t.Errorf("falha permanente não deve ser retentada: %d requisições", e.tg.count())
	}
	var st, lastErr string
	e.pool.QueryRow(ctx, `SELECT status, last_error FROM notification_outbox`).Scan(&st, &lastErr)
	if st != "failed" || !strings.Contains(lastErr, "chat not found") {
		t.Errorf("%s / %s", st, lastErr)
	}
	if strings.Contains(lastErr, "AAH-") || strings.Contains(lastErr, "123456789") {
		t.Errorf("token vazou em last_error: %s", lastErr)
	}
	if testutil.ToFloat64(e.metrics.Notifications.WithLabelValues("failed")) != 1 {
		t.Error("métrica de falhas")
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	e := newEnv(t)
	e.worker.MaxAttempts = 3
	e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e.tg.then(status(500, ``), status(500, ``), status(500, ``), status(500, ``), status(500, ``))
	for i := 0; i < 6; i++ {
		e.tick()
	}
	if e.tg.count() != 3 || e.count(`SELECT count(*) FROM notification_outbox WHERE status='failed' AND attempts=3`) != 1 {
		t.Errorf("deveria desistir após 3 tentativas: reqs=%d", e.tg.count())
	}
}

func TestRateLimitedHonorsRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e.tg.then(status(429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":120}}`))
	e.tick()
	var secs float64
	e.pool.QueryRow(ctx, `SELECT extract(epoch FROM next_attempt_at - now()) FROM notification_outbox`).Scan(&secs)
	if secs < 100 || secs > 125 {
		t.Errorf("deveria aguardar ~120 s (retry_after): %.0f", secs)
	}
	e.tick() // ainda não venceu
	if e.tg.count() != 1 {
		t.Error("não deve reenviar antes do retry_after")
	}
}

func TestNotDueMessagesAreNotSentAndRestartPicksThemUp(t *testing.T) {
	e := newEnv(t)
	e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e.pool.Exec(ctx, `UPDATE notification_outbox SET next_attempt_at = now() + interval '1 hour'`)
	e.tick()
	if e.tg.count() != 0 {
		t.Error("mensagem ainda não vencida não deve ser enviada")
	}
	e.pool.Exec(ctx, `UPDATE notification_outbox SET next_attempt_at = now() - interval '1 second'`)
	// "reinício": worker novo, nada em memória
	fresh := &notifications.Worker{Pool: e.pool, Box: e.box, Channels: e.chans, Sender: notifications.NewTelegram(e.tg.srv.URL),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := fresh.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if e.tg.count() != 1 {
		t.Error("worker novo deveria entregar o que ficou na fila")
	}
}

func TestConcurrentWorkersDeliverEachMessageExactlyOnce(t *testing.T) {
	e := newEnv(t)
	e.channel("critical")
	for i := 0; i < 12; i++ {
		e.enqueue(payload(fmt.Sprintf("%08d-0000-0000-0000-000000000000", i), "critical", notifications.KindTriggered))
	}
	var wg sync.WaitGroup
	for w := 0; w < 5; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wk := *e.worker
			wk.Batch = 3
			for i := 0; i < 6; i++ {
				if err := wk.Tick(ctx); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	seen := map[string]int{}
	for _, tx := range e.tg.texts() {
		seen[tx]++
	}
	if len(seen) != 12 || e.tg.count() != 12 {
		t.Errorf("12 mensagens distintas, cada uma uma vez: distintas=%d total=%d", len(seen), e.tg.count())
	}
	if e.count(`SELECT count(*) FROM notification_outbox WHERE status='sent'`) != 12 {
		t.Error("todas deveriam estar enviadas")
	}
}

func TestDeliveryGuards(t *testing.T) {
	// canal desabilitado
	e := newEnv(t)
	c := e.channel("critical")
	e.enqueue(payload(a1, "critical", notifications.KindTriggered))
	off := false
	e.chans.Update(ctx, actor, c.ID, notifications.UpdateInput{IsEnabled: &off})
	e.tick()
	var lastErr string
	e.pool.QueryRow(ctx, `SELECT last_error FROM notification_outbox`).Scan(&lastErr)
	if e.tg.count() != 0 || e.count(`SELECT count(*) FROM notification_outbox WHERE status='failed'`) != 1 || !strings.Contains(lastErr, "desabilitado") {
		t.Errorf("canal desabilitado: reqs=%d err=%s", e.tg.count(), lastErr)
	}

	// destino removido da lista de autorizados DEPOIS do cadastro: bloqueado no envio
	e2 := newEnv(t)
	e2.channel("critical")
	e2.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e2.worker.Channels = notifications.NewChannelRepository(e2.pool, e2.box, []string{"outro-chat"})
	e2.tick()
	if e2.tg.count() != 0 || e2.count(`SELECT count(*) FROM notification_outbox WHERE status='failed' AND last_error LIKE '%autorizado%'`) != 1 {
		t.Errorf("destino não autorizado no envio: reqs=%d", e2.tg.count())
	}

	// sem SECRETS_KEY no worker
	e3 := newEnv(t)
	e3.channel("critical")
	e3.enqueue(payload(a1, "critical", notifications.KindTriggered))
	e3.worker.Box = nil
	e3.tick()
	if e3.tg.count() != 0 || e3.count(`SELECT count(*) FROM notification_outbox WHERE status='failed'`) != 1 {
		t.Error("sem chave não pode enviar")
	}
}

func TestTestMessageIsDelivered(t *testing.T) {
	e := newEnv(t)
	c := e.channel("critical")
	if err := e.chans.EnqueueTest(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.chans.EnqueueTest(ctx, c.ID); err != nil { // cada teste é uma mensagem nova
		t.Fatal(err)
	}
	e.tick()
	if e.tg.count() != 2 || !strings.Contains(e.tg.texts()[0], "Teste") {
		t.Errorf("%v", e.tg.texts())
	}
	if err := e.chans.EnqueueTest(ctx, "00000000-0000-0000-0000-000000000000"); err != notifications.ErrChannelNotFound {
		t.Errorf("canal inexistente: %v", err)
	}
}
