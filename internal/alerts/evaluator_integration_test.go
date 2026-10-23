//go:build integration

package alerts_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/alerts"
	"sentinela/internal/audit"
	"sentinela/internal/incidents"
	"sentinela/internal/logstore"
	"sentinela/internal/procs"
	"sentinela/internal/testutil"
)

var ctx = context.Background()
var actor = audit.Context{Actor: "teste"}

type fx struct {
	t    *testing.T
	pool *pgxpool.Pool
	now  time.Time // relógio falso compartilhado por todos os avaliadores do teste
	ev   *alerts.Evaluator
	repo *alerts.Repository
	inc  *incidents.Repository
}

func newEvaluator(pool *pgxpool.Pool, f *fx) *alerts.Evaluator {
	return &alerts.Evaluator{
		Pool: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), HeartbeatTimeout: 60 * time.Second,
		Now: func() time.Time { return f.now },
	}
}

func newFx(t *testing.T) *fx {
	t.Helper()
	pool := testutil.NewDB(t)
	f := &fx{t: t, pool: pool, now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		repo: alerts.NewRepository(pool), inc: incidents.NewRepository(pool)}
	f.ev = newEvaluator(pool, f)
	f.repo.Now = func() time.Time { return f.now }
	return f
}

func (f *fx) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(ctx, q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

func (f *fx) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (f *fx) str(q string, args ...any) string {
	f.t.Helper()
	var s *string
	if err := f.pool.QueryRow(ctx, q, args...).Scan(&s); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	if s == nil {
		return ""
	}
	return *s
}

func (f *fx) server(name string) string {
	f.t.Helper()
	var id string
	if err := f.pool.QueryRow(ctx, `INSERT INTO servers (name, hostname) VALUES ($1, $1 || '.local') RETURNING id`, name).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// beat simula o agente no instante atual do relógio falso: amostra + presença.
func (f *fx) beat(server string, cpu float64) {
	f.t.Helper()
	f.exec(`INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, cpu_count, load_average_1m,
			memory_total_bytes, memory_used_bytes, memory_available_bytes) VALUES ($1,$2,$3,4,$4,1000,500,500)`, server, f.now, cpu, cpu/20)
	f.exec(`UPDATE servers SET last_seen_at = $2 WHERE id = $1`, server, f.now)
}

func (f *fx) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *fx) tick() {
	f.t.Helper()
	if err := f.ev.Tick(ctx); err != nil {
		f.t.Fatalf("tick: %v", err)
	}
}

func (f *fx) rule(r alerts.Rule) string {
	f.t.Helper()
	r.IsEnabled = true
	if r.Name == "" {
		r.Name = "regra"
	}
	var id string
	if err := f.pool.QueryRow(ctx, `INSERT INTO alert_rules (name, metric_name, operator, threshold, severity, priority, duration_seconds, recovery_seconds, server_id, is_enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id::text`, r.Name, r.MetricName, r.Operator, r.Threshold, r.Severity,
		max(r.Priority, 1), r.DurationSeconds, r.RecoverySeconds, r.ServerID, r.IsEnabled).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func cpuRule(th float64, dur, rec int) alerts.Rule {
	return alerts.Rule{Name: "CPU alta", MetricName: alerts.MetricCPU, Operator: ">", Threshold: th, Severity: "critical",
		DurationSeconds: dur, RecoverySeconds: rec}
}

func (f *fx) statuses() string {
	rows, _ := f.pool.Query(ctx, `SELECT status FROM alerts ORDER BY triggered_at, id`)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

func TestAlertLifecycleDurationDedupAckRecoveryAndRestart(t *testing.T) {
	f := newFx(t)
	srv := f.server("web-1")
	f.rule(cpuRule(90, 120, 60))

	// t+0: condição verdadeira, mas a duração mínima (120 s) ainda não foi atingida
	f.beat(srv, 95)
	f.tick()
	if f.statuses() != "pending" {
		t.Fatalf("esperava pending: %q", f.statuses())
	}
	list, total, _ := f.repo.ListAlerts(ctx, alerts.AlertListParams{Page: 1, PerPage: 50})
	if total != 0 || len(list) != 0 {
		t.Error("alerta pending não deve aparecer na API")
	}
	if f.count(`SELECT count(*) FROM incidents`) != 0 {
		t.Error("pending não abre incidente")
	}

	// REINÍCIO DA API: um avaliador novo continua do estado persistido (pending_since)
	f.ev = newEvaluator(f.pool, f)
	f.advance(60 * time.Second)
	f.beat(srv, 95)
	f.tick()
	if f.statuses() != "pending" {
		t.Fatalf("aos 60 s ainda pending: %q", f.statuses())
	}

	// t+120: dispara exatamente uma vez
	f.advance(60 * time.Second)
	f.beat(srv, 96)
	f.tick()
	if f.statuses() != "firing" || f.count(`SELECT count(*) FROM incidents WHERE status='open'`) != 1 {
		t.Fatalf("esperava firing + 1 incidente aberto: %q", f.statuses())
	}
	triggered := f.str(`SELECT to_char(triggered_at AT TIME ZONE 'UTC','HH24:MI:SS') FROM alerts`)
	if triggered != "12:02:00" {
		t.Errorf("triggered_at deveria ser o instante da promoção (12:02:00): %s", triggered)
	}
	if msg := f.str(`SELECT message FROM alerts`); !strings.Contains(msg, "96.0%") || !strings.Contains(msg, "> 90%") {
		t.Errorf("mensagem: %s", msg)
	}

	// DEDUPLICAÇÃO: condição contínua por muitas avaliações não cria alertas nem incidentes novos
	for i := 0; i < 10; i++ {
		f.advance(15 * time.Second)
		f.beat(srv, 97+float64(i%3))
		f.tick()
	}
	if f.count(`SELECT count(*) FROM alerts`) != 1 || f.count(`SELECT count(*) FROM incidents`) != 1 {
		t.Fatalf("duplicou: alertas=%d incidentes=%d", f.count(`SELECT count(*) FROM alerts`), f.count(`SELECT count(*) FROM incidents`))
	}
	if v := f.count(`SELECT count(*) FROM alerts WHERE value >= 97`); v != 1 {
		t.Error("o valor observado deveria ser atualizado a cada avaliação")
	}

	// RECONHECIMENTO por operador: muda o estado, registra evento e é idempotente
	id := f.str(`SELECT id::text FROM alerts`)
	a, err := f.repo.Acknowledge(ctx, actor, id, "investigando")
	if err != nil || a.Status != "acknowledged" || a.AcknowledgedAt == nil {
		t.Fatalf("ack: %+v %v", a, err)
	}
	if _, err := f.repo.Acknowledge(ctx, actor, id, "de novo"); err != nil {
		t.Errorf("ack repetido deveria ser idempotente: %v", err)
	}
	if f.count(`SELECT count(*) FROM incident_events WHERE event_type='acknowledged'`) != 1 {
		t.Error("ack repetido não deve duplicar o evento")
	}
	// alerta acknowledged continua sendo o MESMO enquanto a condição persistir
	f.advance(15 * time.Second)
	f.beat(srv, 98)
	f.tick()
	if f.statuses() != "acknowledged" {
		t.Errorf("deveria permanecer acknowledged: %q", f.statuses())
	}

	// RECUPERAÇÃO com recovery_seconds = 60
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.statuses() != "acknowledged" || f.count(`SELECT count(*) FROM alerts WHERE recovering_since IS NOT NULL`) != 1 {
		t.Fatalf("condição normalizou: deveria estar recuperando: %q", f.statuses())
	}
	f.advance(30 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.statuses() != "acknowledged" {
		t.Fatalf("aos 30 s de recuperação ainda ativo: %q", f.statuses())
	}
	// oscilação: volta a subir durante a recuperação => cancela a contagem
	f.advance(15 * time.Second)
	f.beat(srv, 95)
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE recovering_since IS NOT NULL`) != 0 || f.statuses() != "acknowledged" {
		t.Fatalf("oscilação deveria cancelar a recuperação: %q", f.statuses())
	}
	// agora normaliza de verdade
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick() // inicia contagem
	f.advance(60 * time.Second)
	f.beat(srv, 10)
	f.tick() // completa 60 s
	if f.statuses() != "resolved" {
		t.Fatalf("deveria resolver: %q", f.statuses())
	}
	if f.str(`SELECT resolved_reason FROM alerts`) != "recovered" {
		t.Error("resolved_reason")
	}
	if f.count(`SELECT count(*) FROM incidents WHERE status='resolved' AND resolved_at IS NOT NULL`) != 1 {
		t.Error("incidente deveria estar resolvido")
	}
	ev, _ := f.inc.Events(ctx, f.str(`SELECT id::text FROM incidents`))
	var types []string
	for _, e := range ev {
		types = append(types, e.Type)
	}
	if got := strings.Join(types, ","); got != "opened,alert_triggered,acknowledged,alert_resolved,resolved" {
		t.Errorf("linha do tempo do incidente: %s", got)
	}

	// NOVA FALHA depois da resolução: novo alerta E novo incidente (o anterior está encerrado)
	f.advance(30 * time.Second)
	f.beat(srv, 99)
	f.tick()
	f.advance(120 * time.Second)
	f.beat(srv, 99)
	f.tick()
	if f.statuses() != "resolved,firing" || f.count(`SELECT count(*) FROM incidents`) != 2 || f.count(`SELECT count(*) FROM incidents WHERE status='open'`) != 1 {
		t.Errorf("recorrência: alertas=%q incidentes=%d", f.statuses(), f.count(`SELECT count(*) FROM incidents`))
	}
}

func TestShortSpikeNeverBecomesAnAlert(t *testing.T) {
	f := newFx(t)
	srv := f.server("web-1")
	f.rule(cpuRule(90, 120, 0))
	f.beat(srv, 99)
	f.tick() // pending
	f.advance(45 * time.Second)
	f.beat(srv, 20) // normalizou antes de 120 s
	f.tick()
	if f.count(`SELECT count(*) FROM alerts`) != 0 || f.count(`SELECT count(*) FROM incidents`) != 0 || f.count(`SELECT count(*) FROM notification_outbox`) != 0 {
		t.Error("pico curto não deve gerar alerta, incidente nem notificação")
	}
	// novo pico recomeça a contagem do zero
	f.advance(15 * time.Second)
	f.beat(srv, 99)
	f.tick()
	f.advance(100 * time.Second)
	f.beat(srv, 99)
	f.tick()
	if f.statuses() != "pending" {
		t.Errorf("a contagem deveria ter recomeçado (100 s < 120 s): %q", f.statuses())
	}
}

func TestImmediateAlertAndImmediateRecoveryWhenDurationsAreZero(t *testing.T) {
	f := newFx(t)
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))
	f.beat(srv, 95)
	f.tick()
	if f.statuses() != "firing" {
		t.Fatalf("%q", f.statuses())
	}
	f.advance(15 * time.Second)
	f.beat(srv, 50)
	f.tick()
	if f.statuses() != "resolved" {
		t.Fatalf("%q", f.statuses())
	}
}

func TestServerOfflineRuleAndNoDataBehaviour(t *testing.T) {
	f := newFx(t)
	seen := f.server("visto")
	never := f.server("nunca-visto")
	_ = never
	f.beat(seen, 10)
	f.rule(alerts.Rule{Name: "Sem comunicação", MetricName: alerts.MetricOffline, Operator: ">", Threshold: 120, Severity: "critical"})
	f.rule(cpuRule(90, 0, 0))

	f.tick()
	if f.count(`SELECT count(*) FROM alerts`) != 0 {
		t.Fatal("servidor comunicando e servidor nunca visto não devem alertar")
	}
	f.advance(200 * time.Second) // sem novos heartbeats: 200 s de silêncio
	f.tick()
	if f.statuses() != "firing" {
		t.Fatalf("deveria alertar sem comunicação: %q", f.statuses())
	}
	if msg := f.str(`SELECT message FROM alerts`); !strings.Contains(msg, "3 min 20 s") {
		t.Errorf("mensagem: %s", msg)
	}
	// CPU alta NÃO dispara para servidor offline (sem dados atuais), mesmo com a última amostra alta
	f.exec(`UPDATE server_metrics SET cpu_usage_percent = 99`)
	f.advance(15 * time.Second)
	f.tick()
	if f.count(`SELECT count(*) FROM alerts r JOIN alert_rules ar ON ar.id=r.rule_id WHERE ar.metric_name='cpu_usage_percent'`) != 0 {
		t.Error("servidor offline não deve gerar alerta de CPU a partir de amostra velha")
	}
	// volta a comunicar: o alerta de ausência resolve
	f.advance(15 * time.Second)
	f.beat(seen, 10)
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='resolved' AND resolved_reason='recovered'`) != 1 {
		t.Errorf("deveria resolver ao voltar: %q", f.statuses())
	}
}

func TestNoDataKeepsExistingAlertInsteadOfResolvingIt(t *testing.T) {
	f := newFx(t)
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))
	f.beat(srv, 99)
	f.tick()
	if f.statuses() != "firing" {
		t.Fatal(f.statuses())
	}
	f.advance(10 * time.Minute) // servidor ficou offline: sem dados atuais
	f.tick()
	if f.statuses() != "firing" {
		t.Errorf("sem dados não é evidência de recuperação; alerta deveria continuar: %q", f.statuses())
	}
}

func TestScopeGlobalVsServerSpecificAndDeduplicationPerServer(t *testing.T) {
	f := newFx(t)
	a, b := f.server("a"), f.server("b")
	f.beat(a, 99)
	f.beat(b, 99)
	global := f.rule(cpuRule(90, 0, 0))
	scoped := cpuRule(50, 0, 0)
	scoped.Name = "só no A"
	scoped.ServerID = &a
	f.rule(scoped)

	f.tick()
	f.tick()
	f.tick()
	// global: A e B (2) + específica: A (1) = 3, sem duplicar mesmo com 3 avaliações
	if n := f.count(`SELECT count(*) FROM alerts`); n != 3 {
		t.Errorf("alertas: %d (esperado 3)", n)
	}
	if n := f.count(`SELECT count(*) FROM alerts WHERE rule_id=$1`, global); n != 2 {
		t.Errorf("global deveria cobrir os dois servidores: %d", n)
	}
	if n := f.count(`SELECT count(*) FROM incidents`); n != 3 {
		t.Errorf("incidentes: %d", n)
	}
}

func TestOutOfScopeResolvesAlerts(t *testing.T) {
	f := newFx(t)
	a, b, c := f.server("a"), f.server("b"), f.server("c")
	for _, s := range []string{a, b, c} {
		f.beat(s, 99)
	}
	f.rule(cpuRule(90, 0, 0))
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='firing'`) != 3 {
		t.Fatal("setup")
	}
	f.exec(`UPDATE servers SET status='maintenance' WHERE id=$1`, a)
	f.exec(`UPDATE servers SET deleted_at=now() WHERE id=$1`, b)
	f.exec(`UPDATE servers SET status='disabled' WHERE id=$1`, c)
	f.advance(15 * time.Second)
	f.tick()
	if n := f.count(`SELECT count(*) FROM alerts WHERE status='resolved' AND resolved_reason='out_of_scope'`); n != 3 {
		t.Errorf("manutenção/remoção/desativação deveriam resolver os 3: %d (%q)", n, f.statuses())
	}
	if f.count(`SELECT count(*) FROM incidents WHERE status='open'`) != 0 {
		t.Error("incidentes deveriam fechar")
	}
}

// Regras fora do catálogo (cadastradas antes da automação) são arquivadas na sincronização e os
// alertas delas são resolvidos pelo avaliador; o histórico fica.
func TestSyncingCatalogArchivesLegacyRulesAndResolvesTheirAlerts(t *testing.T) {
	f := newFx(t)
	srv := f.server("web")
	f.beat(srv, 99)
	r1 := f.rule(cpuRule(90, 0, 0))
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='firing'`) != 1 {
		t.Fatal("setup")
	}
	if err := alerts.SyncCatalog(ctx, f.pool); err != nil {
		t.Fatal(err)
	}
	f.advance(15 * time.Second)
	f.beat(srv, 99) // o catálogo (CPU > 90 por 5 min) ainda não dispara
	f.tick()
	if f.str(`SELECT resolved_reason FROM alerts WHERE rule_id=$1`, r1) != "rule_deleted" {
		t.Errorf("motivo: %q", f.statuses())
	}
	if _, err := f.repo.GetRule(ctx, r1); err != alerts.ErrRuleNotFound {
		t.Errorf("regra arquivada não deve ser visível: %v", err)
	}
	if f.count(`SELECT count(*) FROM alerts WHERE rule_id=$1`, r1) != 1 {
		t.Error("histórico de alertas deve ser preservado")
	}
}

func TestCatalogDetectsSwapAndLoadPerCPU(t *testing.T) {
	f := newFx(t)
	f.pool.Exec(ctx, `DELETE FROM alert_rules`)
	if err := alerts.SyncCatalog(ctx, f.pool); err != nil {
		t.Fatal(err)
	}
	srv := f.server("web")
	f.beat(srv, 10)
	f.pool.Exec(ctx, `UPDATE server_metrics SET cpu_count=2, load_average_1m=6, swap_total_bytes=1000, swap_used_bytes=900 WHERE server_id=$1`, srv)
	f.tick()
	f.advance(11 * time.Minute) // acima da duração de todas as regras
	f.beat(srv, 10)
	f.pool.Exec(ctx, `UPDATE server_metrics SET cpu_count=2, load_average_1m=6, swap_total_bytes=1000, swap_used_bytes=900 WHERE server_id=$1`, srv)
	f.tick()
	got := f.str(`SELECT string_agg(r.code || ':P' || i.priority, ',' ORDER BY r.code) FROM incidents i JOIN alert_rules r ON r.id=i.rule_id`)
	if got != "load_high:P2,swap_high:P3" {
		t.Errorf("incidentes: %q", got)
	}
	if f.str(`SELECT message FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.code='load_high'`) != "Load average de 3.00 por CPU (limite: > 2)" {
		t.Error("mensagem de load")
	}
}

func TestRecurrentIncidentIsFlagged(t *testing.T) {
	f := newFx(t)
	srv := f.server("web")
	rule := cpuRule(90, 0, 0)
	rule.Priority = alerts.P2
	f.rule(rule)
	for i := 0; i < 2; i++ {
		f.beat(srv, 99)
		f.tick() // abre
		f.advance(15 * time.Second)
		f.beat(srv, 10)
		f.tick() // resolve
		f.advance(15 * time.Second)
	}
	f.beat(srv, 99)
	f.tick() // terceira vez: reincidente (2 resolvidos nas últimas 24 h)
	if got := f.count(`SELECT recurrence_count FROM incidents WHERE status='open'`); got != 2 {
		t.Errorf("recurrence_count = %d", got)
	}
	if f.count(`SELECT count(*) FROM incident_events e JOIN incidents i ON i.id=e.incident_id WHERE i.status='open' AND e.event_type='recurrent'`) != 1 {
		t.Error("o incidente reincidente deve registrar o evento na linha do tempo")
	}
	if f.count(`SELECT priority FROM incidents WHERE status='open'`) != 2 {
		t.Error("o incidente herda a prioridade da regra")
	}
}

func TestServiceDownRule(t *testing.T) {
	f := newFx(t)
	f.pool.Exec(ctx, `DELETE FROM alert_rules`) // a migração cria uma regra service_down padrão
	srv := f.server("web")
	f.beat(srv, 10)
	var httpSvc, tcpSvc string
	f.pool.QueryRow(ctx, `INSERT INTO monitored_services (server_id,name,service_type,target,status,last_error) VALUES ($1,'api','http','https://x.example.com','up',NULL) RETURNING id`, srv).Scan(&httpSvc)
	f.pool.QueryRow(ctx, `INSERT INTO monitored_services (server_id,name,service_type,target,status) VALUES ($1,'nginx','systemd','nginx','up') RETURNING id`, srv).Scan(&tcpSvc)
	f.rule(alerts.Rule{Name: "Serviço fora", MetricName: alerts.MetricServiceDown, Operator: "==", Threshold: 1, Severity: "critical", DurationSeconds: 0})

	f.tick()
	if f.count(`SELECT count(*) FROM alerts`) != 0 {
		t.Fatal("serviços up não alertam")
	}
	f.exec(`UPDATE monitored_services SET status='down', last_error='tempo limite excedido' WHERE id=$1`, httpSvc)
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.statuses() != "firing" {
		t.Fatalf("%q", f.statuses())
	}
	if msg := f.str(`SELECT message FROM alerts`); !strings.Contains(msg, `"api"`) || !strings.Contains(msg, "tempo limite excedido") {
		t.Errorf("mensagem: %s", msg)
	}
	if f.str(`SELECT service_id::text FROM alerts`) != httpSvc || !strings.Contains(f.str(`SELECT title FROM incidents`), "api") {
		t.Error("alerta/incidente deveriam referenciar o serviço")
	}
	// um segundo serviço fora gera OUTRO alerta (chave inclui o serviço)
	f.exec(`UPDATE monitored_services SET status='down' WHERE id=$1`, tcpSvc)
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='firing'`) != 2 {
		t.Errorf("%q", f.statuses())
	}
	// unknown não avalia nem resolve
	f.exec(`UPDATE monitored_services SET status='unknown' WHERE id=$1`, httpSvc)
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='firing'`) != 2 {
		t.Error("estado unknown deve manter o alerta")
	}
	// recuperação
	f.exec(`UPDATE monitored_services SET status='up'`)
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='resolved'`) != 2 {
		t.Errorf("%q", f.statuses())
	}
	// serviço verificado pelo agente com o servidor offline: estado velho não é confiável
	f.exec(`UPDATE monitored_services SET status='down' WHERE id=$1`, tcpSvc)
	f.advance(10 * time.Minute) // sem heartbeats
	f.tick()
	if f.count(`SELECT count(*) FROM alerts WHERE status='firing' AND service_id=$1`, tcpSvc) != 0 {
		t.Error("serviço de agente com servidor offline não deve disparar a partir de estado velho")
	}
	// serviço removido
	f.exec(`UPDATE monitored_services SET deleted_at=now() WHERE id=$1`, httpSvc)
}

func TestDiskLoadAndMemoryRules(t *testing.T) {
	f := newFx(t)
	srv := f.server("web")
	f.beat(srv, 10)
	f.exec(`INSERT INTO server_disks (server_id, mount_point, total_bytes, used_bytes, available_bytes, collected_at) VALUES
		($1,'/',1000,500,500,now()), ($1,'/data',1000,900,100,now())`, srv)
	f.rule(alerts.Rule{Name: "Disco", MetricName: alerts.MetricDisk, Operator: ">", Threshold: 85, Severity: "critical"})
	f.rule(alerts.Rule{Name: "Mem", MetricName: alerts.MetricMemory, Operator: ">=", Threshold: 50, Severity: "warning"})
	f.rule(alerts.Rule{Name: "Load", MetricName: alerts.MetricLoad, Operator: ">", Threshold: 100, Severity: "info"})
	f.tick()
	if n := f.count(`SELECT count(*) FROM alerts WHERE status='firing'`); n != 2 {
		t.Fatalf("disco (pior volume) e memória deveriam disparar; load não: %d %q", n, f.statuses())
	}
	if msg := f.str(`SELECT a.message FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.name='Disco'`); !strings.Contains(msg, "/data") || !strings.Contains(msg, "90.0%") {
		t.Errorf("a mensagem de disco deve citar o pior volume: %s", msg)
	}
}

func TestConcurrentEvaluatorsCreateExactlyOneAlert(t *testing.T) {
	f := newFx(t)
	srv := f.server("web")
	f.beat(srv, 99)
	f.rule(cpuRule(90, 0, 0))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := newEvaluator(f.pool, f) // "várias instâncias da API"
			if err := ev.Tick(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.count(`SELECT count(*) FROM alerts`) != 1 || f.count(`SELECT count(*) FROM incidents`) != 1 {
		t.Errorf("alertas=%d incidentes=%d", f.count(`SELECT count(*) FROM alerts`), f.count(`SELECT count(*) FROM incidents`))
	}
}

func TestManualResolveAndStateGuards(t *testing.T) {
	f := newFx(t)
	srv := f.server("web")
	f.beat(srv, 99)
	f.rule(cpuRule(90, 0, 0))
	f.tick()
	id := f.str(`SELECT id::text FROM alerts`)

	a, err := f.repo.ResolveManual(ctx, actor, id)
	if err != nil || a.Status != "resolved" || a.ResolvedReason == nil || *a.ResolvedReason != "manual" {
		t.Fatalf("%+v %v", a, err)
	}
	if f.count(`SELECT count(*) FROM incidents WHERE status='resolved'`) != 1 {
		t.Error("o incidente deve fechar junto")
	}
	if _, err := f.repo.ResolveManual(ctx, actor, id); err != alerts.ErrInvalidState {
		t.Errorf("resolver de novo: %v", err)
	}
	if _, err := f.repo.Acknowledge(ctx, actor, id, ""); err != alerts.ErrInvalidState {
		t.Errorf("reconhecer alerta resolvido: %v", err)
	}
	if _, err := f.repo.Acknowledge(ctx, actor, "00000000-0000-0000-0000-000000000000", ""); err != alerts.ErrAlertNotFound {
		t.Errorf("inexistente: %v", err)
	}
	// condição persiste => o avaliador abre um NOVO alerta (documentado)
	f.advance(15 * time.Second)
	f.beat(srv, 99)
	f.tick()
	if f.statuses() != "resolved,firing" {
		t.Errorf("%q", f.statuses())
	}
}

func TestAlertsListFilteringAndIncidentQueries(t *testing.T) {
	f := newFx(t)
	a, b := f.server("a"), f.server("b")
	f.beat(a, 99)
	f.beat(b, 99)
	ruleCrit := f.rule(cpuRule(90, 0, 0))
	warn := cpuRule(95, 0, 0)
	warn.Name, warn.Severity = "aviso", "warning"
	f.rule(warn)
	f.tick() // 4 alertas: 2 regras x 2 servidores
	f.advance(time.Minute)
	f.beat(b, 10)
	f.tick() // resolve os de b

	list := func(p alerts.AlertListParams) (int, []alerts.Alert) {
		p.Page, p.PerPage = 1, 50
		l, n, err := f.repo.ListAlerts(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return n, l
	}
	if n, _ := list(alerts.AlertListParams{}); n != 4 {
		t.Errorf("todos: %d", n)
	}
	if n, _ := list(alerts.AlertListParams{Status: "active"}); n != 2 {
		t.Errorf("ativos: %d", n)
	}
	if n, _ := list(alerts.AlertListParams{Status: "resolved"}); n != 2 {
		t.Errorf("resolvidos: %d", n)
	}
	if n, _ := list(alerts.AlertListParams{Severity: "warning"}); n != 2 {
		t.Errorf("severidade: %d", n)
	}
	if n, _ := list(alerts.AlertListParams{ServerID: a}); n != 2 {
		t.Errorf("servidor: %d", n)
	}
	if n, _ := list(alerts.AlertListParams{RuleID: ruleCrit}); n != 2 {
		t.Errorf("regra: %d", n)
	}
	from, to := f.now.Add(-time.Hour), f.now.Add(-30*time.Second)
	if n, _ := list(alerts.AlertListParams{From: &from, To: &to}); n != 4 {
		t.Errorf("período: %d", n)
	}
	later := f.now.Add(time.Hour)
	if n, _ := list(alerts.AlertListParams{From: &later}); n != 0 {
		t.Errorf("período futuro: %d", n)
	}
	_, l := list(alerts.AlertListParams{Status: "active"})
	if l[0].ServerName != "a" || l[0].RuleName == "" || l[0].IncidentID == nil {
		t.Errorf("campos relacionados: %+v", l[0])
	}

	// incidentes
	incs, total, err := f.inc.List(ctx, incidents.ListParams{Page: 1, PerPage: 50})
	if err != nil || total != 4 || len(incs) != 4 {
		t.Fatalf("incidentes: %d %v", total, err)
	}
	if _, n, _ := f.inc.List(ctx, incidents.ListParams{Page: 1, PerPage: 50, Status: "open"}); n != 2 {
		t.Errorf("abertos: %d", n)
	}
	if _, n, _ := f.inc.List(ctx, incidents.ListParams{Page: 1, PerPage: 50, ServerID: b, Status: "resolved"}); n != 2 {
		t.Errorf("resolvidos de b: %d", n)
	}
	var resolved incidents.Incident
	for _, i := range incs {
		if i.Status == "resolved" {
			resolved = i
			break
		}
	}
	d, err := f.inc.Get(ctx, resolved.ID)
	if err != nil || len(d.Alerts) != 1 || d.Alerts[0].Status != "resolved" || d.DurationSeconds != 60 || d.ServerName == nil {
		t.Errorf("detalhe: %+v %v", d, err)
	}
	if _, err := f.inc.Get(ctx, "00000000-0000-0000-0000-000000000000"); err != incidents.ErrNotFound {
		t.Errorf("inexistente: %v", err)
	}
	if _, err := f.inc.Events(ctx, "00000000-0000-0000-0000-000000000000"); err != incidents.ErrNotFound {
		t.Errorf("eventos de inexistente: %v", err)
	}
}

// Rede de segurança: se já existir um incidente ABERTO para a mesma falha (servidor, regra, serviço),
// um novo alerta o reutiliza em vez de criar outro (também garantido pelo índice único parcial).
func TestNewAlertReusesAnAlreadyOpenIncident(t *testing.T) {
	f := newFx(t)
	srv := f.server("web-1")
	f.beat(srv, 99)
	ruleID := f.rule(cpuRule(90, 0, 0))
	var incID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO incidents (server_id, rule_id, title, severity) VALUES ($1,$2,'preexistente','critical') RETURNING id`, srv, ruleID).Scan(&incID); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if f.count(`SELECT count(*) FROM incidents`) != 1 {
		t.Fatalf("deveria reutilizar o incidente aberto: %d incidentes", f.count(`SELECT count(*) FROM incidents`))
	}
	if f.str(`SELECT incident_id::text FROM alerts`) != incID {
		t.Error("o alerta deveria referenciar o incidente existente")
	}
	// o índice único parcial impede um segundo incidente aberto idêntico mesmo por outro caminho
	if _, err := f.pool.Exec(ctx, `INSERT INTO incidents (server_id, rule_id, title, severity) VALUES ($1,$2,'duplicado','critical')`, srv, ruleID); err == nil {
		t.Error("o banco deveria recusar um segundo incidente aberto para a mesma falha")
	}
}

type fakeSystem struct {
	ready bool
	err   error
	vals  []logstore.SystemValue
}

func (s *fakeSystem) Ready() bool { return s.ready }
func (s *fakeSystem) LatestSystem(context.Context, time.Duration) ([]logstore.SystemValue, error) {
	return s.vals, s.err
}

func TestCatalogEvaluatesSystemMetricsFromClickHouse(t *testing.T) {
	f := newFx(t)
	f.pool.Exec(ctx, `DELETE FROM alert_rules`)
	if err := alerts.SyncCatalog(ctx, f.pool); err != nil {
		t.Fatal(err)
	}
	srv := f.server("web")
	f.beat(srv, 10)
	sys := &fakeSystem{ready: true, vals: []logstore.SystemValue{
		{ServerID: srv, Metric: "oom_kills", Latest: 1, Sum: 3},
		{ServerID: srv, Metric: "inode_used_percent", Subject: "/", Latest: 40},
		{ServerID: srv, Metric: "inode_used_percent", Subject: "/data", Latest: 97},
		{ServerID: srv, Metric: "cert_days_left", Subject: "a.exemplo.com", Latest: 30},
		{ServerID: srv, Metric: "cert_days_left", Subject: "b.exemplo.com", Latest: 1.5},
		{ServerID: srv, Metric: "ntp_unsynchronized", Latest: 0},
	}}
	f.ev.System = sys
	f.tick()
	f.advance(2*time.Hour + time.Minute) // acima de qualquer duração do catálogo
	f.beat(srv, 10)
	f.tick()
	got := f.str(`SELECT string_agg(r.code || ':P' || i.priority, ',' ORDER BY r.code) FROM incidents i JOIN alert_rules r ON r.id=i.rule_id`)
	if got != "cert_critical:P2,cert_expiring:P3,inodes_high:P2,oom_kill:P2" {
		t.Errorf("incidentes: %q", got)
	}
	if m := f.str(`SELECT a.message FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.code='inodes_high'`); !strings.Contains(m, "/data") || !strings.Contains(m, "97.0%") {
		t.Errorf("o pior volume deve aparecer: %q", m)
	}
	if m := f.str(`SELECT a.message FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.code='cert_critical'`); !strings.Contains(m, "b.exemplo.com") {
		t.Errorf("o pior certificado deve aparecer: %q", m)
	}

	// ClickHouse fora do ar: nada abre nem resolve
	sys.err = errors.New("clickhouse fora")
	sys.vals = nil
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if f.count(`SELECT count(*) FROM incidents WHERE status='open'`) != 4 {
		t.Error("sem dados, os incidentes abertos devem permanecer")
	}
	// dados voltam normalizados: resolve
	sys.err = nil
	sys.vals = []logstore.SystemValue{{ServerID: srv, Metric: "oom_kills", Sum: 0}, {ServerID: srv, Metric: "inode_used_percent", Subject: "/", Latest: 10},
		{ServerID: srv, Metric: "cert_days_left", Subject: "a.exemplo.com", Latest: 80}}
	f.advance(5 * time.Hour) // acima da recuperação de 1 h dos certificados
	f.beat(srv, 10)
	f.tick()
	f.advance(61 * time.Minute) // cumpre a recuperação de 1 h dos certificados
	f.beat(srv, 10)
	f.tick()
	if n := f.count(`SELECT count(*) FROM incidents WHERE status='open'`); n != 0 {
		t.Errorf("incidentes abertos após normalizar: %d", n)
	}
}

// Toda notificação de alerta (qualquer prioridade, com ou sem canal externo) fica registrada no PostgreSQL.
func TestEveryAlertIsRecordedAsNotification(t *testing.T) {
	f := newFx(t)
	srv := f.server("web")
	f.beat(srv, 99)
	crit := cpuRule(90, 0, 0)
	crit.Priority = alerts.P1
	f.rule(crit)
	info := cpuRule(10, 0, 0)
	info.Name, info.Severity, info.Priority = "CPU levemente usada", "info", alerts.P4
	f.rule(info)
	f.tick()
	if n := f.count(`SELECT count(*) FROM notifications WHERE kind='alert_triggered'`); n != 2 {
		t.Fatalf("2 alertas disparados deveriam virar 2 notificações, vieram %d", n)
	}
	f.tick() // condição persistente não repete
	if f.count(`SELECT count(*) FROM notifications`) != 2 {
		t.Error("a mesma condição não pode gerar notificações repetidas")
	}
	if f.count(`SELECT count(*) FROM notifications WHERE kind='alert_triggered' AND priority=1 AND severity='critical' AND server_id IS NOT NULL AND incident_id IS NOT NULL`) != 1 {
		t.Error("prioridade/severidade/vínculos devem ser gravados")
	}
	f.advance(15 * time.Second)
	f.beat(srv, 1)
	f.tick() // recuperação
	if n := f.count(`SELECT count(*) FROM notifications WHERE kind='alert_resolved' AND priority=4 AND severity='info' AND title LIKE 'Recuperado:%'`); n != 2 {
		t.Errorf("recuperações registradas (P4): %d", n)
	}
}

type fakeProcs struct {
	ready   bool
	err     error
	list    []procs.Culprit
	samples int
	kinds   []string
}

func (p *fakeProcs) Ready() bool { return p.ready }
func (p *fakeProcs) ProcCulprits(_ context.Context, _ string, _, _ time.Time, kind string, _ int) ([]procs.Culprit, int, error) {
	p.kinds = append(p.kinds, kind)
	return p.list, p.samples, p.err
}

// O alerta de CPU/memória aponta os maiores consumidores: do histórico quando existe, da última leitura quando não.
func TestAlertNamesTheProcessesBehindCPUAndMemory(t *testing.T) {
	f := newFx(t)
	f.pool.Exec(ctx, `DELETE FROM alert_rules`)
	if err := alerts.SyncCatalog(ctx, f.pool); err != nil {
		t.Fatal(err)
	}
	srv := f.server("web")
	hist := &fakeProcs{ready: true, samples: 10, list: []procs.Culprit{
		{Name: "node", User: "app", CPUPercent: 85.5, CPUPeak: 100, MemoryBytes: 400 << 20},
		{Name: "backup", User: "root", CPUPercent: 7, CPUPeak: 60, MemoryBytes: 10 << 20}}}
	f.ev.Procs = hist
	cpuHigh := func() {
		f.beat(srv, 96)
		f.tick()
		f.advance(6 * time.Minute) // acima da duração de 5 min
		f.beat(srv, 96)
		f.tick()
	}
	cpuHigh()
	msg := f.str(`SELECT a.message FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.code='cpu_high'`)
	if !strings.Contains(msg, "Uso de CPU em 96.0%") || !strings.Contains(msg, "Maiores consumidores de CPU (média dos últimos 5 min): node 85.5% de CPU, backup 7.0% de CPU.") {
		t.Fatalf("mensagem: %q", msg)
	}
	if len(hist.kinds) == 0 || hist.kinds[0] != "cpu" {
		t.Errorf("tipo consultado: %v", hist.kinds)
	}
	raw := f.str(`SELECT a.culprits::text FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.code='cpu_high'`)
	var c procs.Culprits
	if err := json.Unmarshal([]byte(raw), &c); err != nil || c.Source != "history" || c.Kind != "cpu" || len(c.Processes) != 2 || c.Processes[0].Name != "node" || c.WindowSeconds != 300 {
		t.Errorf("culprits gravado: %s %v", raw, err)
	}
	// a API devolve o campo no alerta e no incidente
	list, _, err := f.repo.ListAlerts(ctx, alerts.AlertListParams{Page: 1, PerPage: 50})
	if err != nil || len(list) == 0 || !strings.Contains(string(list[0].Culprits), `"node"`) {
		t.Errorf("culprits na API: %v %v", list, err)
	}
	var incID string
	if err := f.pool.QueryRow(ctx, `SELECT incident_id::text FROM alerts LIMIT 1`).Scan(&incID); err != nil {
		t.Fatal(err)
	}
	if d, err := f.inc.Get(ctx, incID); err != nil || len(d.Alerts) != 1 || !strings.Contains(string(d.Alerts[0].Culprits), `"node"`) {
		t.Errorf("culprits no incidente: %+v %v", d, err)
	}
	if n := f.count(`SELECT count(*) FROM notifications WHERE message LIKE '%node 85.5%'`); n == 0 {
		t.Error("a notificação deve trazer os consumidores")
	}

	// Sem histórico: usa a última leitura de processos (se for recente) para a regra de memória.
	f.ev.Procs = &fakeProcs{ready: true, samples: 0}
	rep := procs.Report{CheckedAt: f.now, CPUs: 4, MemoryTotalBytes: 1 << 30, Processes: []procs.Process{
		{PID: 1, Name: "java", User: "app", State: "S", MemoryBytes: 700 << 20},
		{PID: 2, Name: "redis", User: "redis", State: "S", MemoryBytes: 100 << 20}}}
	if err := procs.NewRepository(f.pool).Replace(ctx, srv, rep); err != nil {
		t.Fatal(err)
	}
	f.pool.Exec(ctx, `UPDATE server_metrics SET memory_used_bytes = 950`)
	f.advance(time.Minute)
	f.exec(`INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, cpu_count, load_average_1m, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		VALUES ($1,$2,10,4,0.5,1000,950,50)`, srv, f.now)
	f.exec(`UPDATE servers SET last_seen_at = $2 WHERE id = $1`, srv, f.now)
	f.tick()
	f.advance(3 * time.Minute) // acima da duração de 2 min
	f.exec(`INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, cpu_count, load_average_1m, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		VALUES ($1,$2,10,4,0.5,1000,950,50)`, srv, f.now)
	f.exec(`UPDATE servers SET last_seen_at = $2 WHERE id = $1`, srv, f.now)
	rep.CheckedAt = f.now.Add(-20 * time.Second)
	if err := procs.NewRepository(f.pool).Replace(ctx, srv, rep); err != nil {
		t.Fatal(err)
	}
	f.tick()
	msg = f.str(`SELECT a.message FROM alerts a JOIN alert_rules r ON r.id=a.rule_id WHERE r.code='memory_low'`)
	if !strings.Contains(msg, "Maiores consumidores de memória (na última leitura): java 700 MB, redis 100 MB.") {
		t.Errorf("fallback para a última leitura: %q", msg)
	}

	// Regras sem relação com processos (disco) não consultam nem anexam nada.
	if k := len(hist.kinds); k == 0 {
		t.Error("o histórico deveria ter sido consultado")
	}
}
