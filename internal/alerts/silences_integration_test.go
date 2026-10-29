//go:build integration

package alerts_test

import (
	"testing"
	"time"

	"sentinela/internal/silences"
)

func (f *fx) channel() {
	f.t.Helper()
	f.exec(`INSERT INTO notification_channels (name, channel_type, config) VALUES ('tg', 'telegram', '{"min_severity":"info"}')`)
}

func (f *fx) silence(server, rule *string, d time.Duration) silences.Silence {
	f.t.Helper()
	repo := silences.NewRepository(f.pool)
	repo.Now = func() time.Time { return f.now }
	in := silences.CreateInput{Kind: silences.KindMaintenance, Reason: "deploy", ServerID: server, RuleID: rule}
	mins := int(d / time.Minute)
	in.DurationMinutes = &mins
	if p := in.Validate(f.now); len(p) > 0 {
		f.t.Fatalf("validação: %v", p)
	}
	s, err := repo.Create(ctx, actor, in)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// fireCPU leva o servidor a um alerta firing (regra com duração zero).
func (f *fx) fireCPU(srv string) {
	f.t.Helper()
	f.beat(srv, 99)
	f.tick()
}

func TestSilencedAlertIsRecordedButNotNotified(t *testing.T) {
	f := newFx(t)
	f.channel()
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))
	f.silence(&srv, nil, time.Hour)

	f.fireCPU(srv)

	if f.statuses() != "firing" || f.count(`SELECT count(*) FROM incidents WHERE status='open'`) != 1 {
		t.Fatalf("o alerta e o incidente devem existir mesmo silenciados: %q", f.statuses())
	}
	if f.count(`SELECT count(*) FROM notification_outbox`) != 0 {
		t.Error("silenciado não pode enfileirar para os canais")
	}
	if f.count(`SELECT count(*) FROM notifications WHERE data->>'silenced' = 'true'`) != 1 {
		t.Error("o registro do painel deve existir, marcado como silenciado")
	}
	if f.count(`SELECT count(*) FROM alerts WHERE silenced`) != 1 {
		t.Error("alerts.silenced deveria ser true")
	}
	if f.count(`SELECT count(*) FROM incident_events WHERE event_type = 'silenced'`) != 1 {
		t.Error("o incidente deveria registrar o silenciamento")
	}
}

func TestSilenceScopeServerAndRule(t *testing.T) {
	f := newFx(t)
	f.channel()
	a, b := f.server("a"), f.server("b")
	f.rule(cpuRule(90, 0, 0))
	f.silence(&a, nil, time.Hour) // só o servidor a

	f.beat(a, 99)
	f.beat(b, 99)
	f.tick()

	if f.count(`SELECT count(*) FROM alerts`) != 2 {
		t.Fatalf("os dois servidores devem ter alerta")
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox`); n != 1 {
		t.Fatalf("só o servidor fora da janela notifica: outbox=%d", n)
	}
	if f.count(`SELECT count(*) FROM alerts WHERE silenced AND server_id = $1`, a) != 1 {
		t.Error("o alerta do servidor silenciado deveria estar marcado")
	}

	// uma regra diferente da silenciada não é afetada
	other := f.rule(cpuRule(10, 0, 0))
	f.silence(&b, &other, time.Hour)
	if got := f.count(`SELECT count(*) FROM alert_silences`); got != 2 {
		t.Fatalf("silenciamentos: %d", got)
	}
}

func TestSilencedAlertNotifiesWhenWindowEndsIfStillOpen(t *testing.T) {
	f := newFx(t)
	f.channel()
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))
	f.silence(&srv, nil, 30*time.Minute)
	f.fireCPU(srv)

	// dentro da janela: nada sai
	f.advance(15 * time.Minute)
	f.beat(srv, 99)
	f.tick()
	if f.count(`SELECT count(*) FROM notification_outbox`) != 0 {
		t.Fatal("nada deve sair durante a janela")
	}

	// a janela termina e o problema continua: avisa uma única vez
	f.advance(20 * time.Minute)
	f.beat(srv, 99)
	f.tick()
	f.advance(15 * time.Second)
	f.beat(srv, 99)
	f.tick()
	if n := f.count(`SELECT count(*) FROM notification_outbox`); n != 1 {
		t.Fatalf("deveria enviar exatamente 1 notificação ao fim da janela: %d", n)
	}
	if f.count(`SELECT count(*) FROM alerts WHERE silenced`) != 0 {
		t.Error("a marca silenced deve ser limpa")
	}
	if f.count(`SELECT count(*) FROM incident_events WHERE event_type = 'silence_ended'`) != 1 {
		t.Error("o incidente deveria registrar o fim do silenciamento")
	}

	// agora a recuperação é enviada, pois o disparo chegou ao canal
	f.advance(15 * time.Second)
	f.beat(srv, 10)
	f.tick()
	if n := f.count(`SELECT count(*) FROM notification_outbox`); n != 2 {
		t.Fatalf("recuperação deveria ser enviada: outbox=%d", n)
	}
}

func TestSilencedAlertThatRecoversInsideWindowSendsNothing(t *testing.T) {
	f := newFx(t)
	f.channel()
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))
	f.silence(&srv, nil, time.Hour)
	f.fireCPU(srv)

	f.advance(30 * time.Second)
	f.beat(srv, 10)
	f.tick()

	if f.statuses() != "resolved" {
		t.Fatalf("o alerta deveria resolver normalmente: %q", f.statuses())
	}
	if n := f.count(`SELECT count(*) FROM notification_outbox`); n != 0 {
		t.Fatalf("nem disparo nem recuperação devem sair: outbox=%d", n)
	}
}

func TestCancelledSilenceStopsSuppressing(t *testing.T) {
	f := newFx(t)
	f.channel()
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))
	s := f.silence(&srv, nil, time.Hour)

	repo := silences.NewRepository(f.pool)
	repo.Now = func() time.Time { return f.now }
	got, err := repo.Cancel(ctx, actor, s.ID)
	if err != nil || got.Status != silences.StatusCancelled {
		t.Fatalf("cancelar: %+v %v", got, err)
	}
	if again, err := repo.Cancel(ctx, actor, s.ID); err != nil || again.Status != silences.StatusCancelled {
		t.Fatalf("cancelar é idempotente: %+v %v", again, err)
	}

	f.fireCPU(srv)
	if n := f.count(`SELECT count(*) FROM notification_outbox`); n != 1 {
		t.Fatalf("sem janela ativa a notificação sai: outbox=%d", n)
	}
}

func TestScheduledSilenceOnlyStartsLater(t *testing.T) {
	f := newFx(t)
	f.channel()
	srv := f.server("web-1")
	f.rule(cpuRule(90, 0, 0))

	repo := silences.NewRepository(f.pool)
	repo.Now = func() time.Time { return f.now }
	start, end := f.now.Add(time.Hour), f.now.Add(2*time.Hour)
	in := silences.CreateInput{Kind: silences.KindMaintenance, Reason: "janela", ServerID: &srv, StartsAt: &start, EndsAt: &end}
	if p := in.Validate(f.now); len(p) > 0 {
		t.Fatal(p)
	}
	s, err := repo.Create(ctx, actor, in)
	if err != nil || s.Status != silences.StatusScheduled {
		t.Fatalf("deveria estar agendado: %+v %v", s, err)
	}

	f.fireCPU(srv) // ainda não começou
	if n := f.count(`SELECT count(*) FROM notification_outbox`); n != 1 {
		t.Fatalf("antes do início a notificação sai: %d", n)
	}
	list, total, err := repo.List(ctx, silences.ListParams{Page: 1, PerPage: 10, Status: silences.StatusActive})
	if err != nil || total != 0 || len(list) != 0 {
		t.Errorf("agendado não é ativo: %v %d", err, total)
	}
}
