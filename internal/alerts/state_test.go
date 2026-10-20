package alerts

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
func tp(sec int) *time.Time {
	t := at(sec)
	return &t
}

func TestDecideTable(t *testing.T) {
	cases := []struct {
		name     string
		st       State
		cond     bool
		now      int
		dur, rec int
		want     Action
	}{
		// sem alerta
		{"sem alerta, condição falsa", State{}, false, 0, 60, 0, ActNone},
		{"sem alerta, condição verdadeira, sem duração", State{}, true, 0, 0, 0, ActFire},
		{"sem alerta, condição verdadeira, com duração", State{}, true, 0, 60, 0, ActStartPending},
		// pending
		{"pending, antes da duração", State{Exists: true, Status: StatusPending, PendingSince: tp(0)}, true, 59, 60, 0, ActNone},
		{"pending, exatamente na duração", State{Exists: true, Status: StatusPending, PendingSince: tp(0)}, true, 60, 60, 0, ActFire},
		{"pending, depois da duração", State{Exists: true, Status: StatusPending, PendingSince: tp(0)}, true, 300, 60, 0, ActFire},
		{"pending, condição some (oscilação curta)", State{Exists: true, Status: StatusPending, PendingSince: tp(0)}, false, 30, 60, 0, ActDropPending},
		{"pending sem pending_since (dado inconsistente) dispara", State{Exists: true, Status: StatusPending}, true, 5, 60, 0, ActFire},
		// firing / acknowledged: deduplicação — condição contínua não gera nada novo
		{"firing, condição continua", State{Exists: true, Status: StatusFiring}, true, 999, 0, 0, ActNone},
		{"acknowledged, condição continua", State{Exists: true, Status: StatusAcknowledged}, true, 999, 0, 0, ActNone},
		// recuperação
		{"firing, recuperou, sem recovery", State{Exists: true, Status: StatusFiring}, false, 0, 0, 0, ActResolve},
		{"acknowledged, recuperou, sem recovery", State{Exists: true, Status: StatusAcknowledged}, false, 0, 0, 0, ActResolve},
		{"firing, recuperou, inicia contagem", State{Exists: true, Status: StatusFiring}, false, 0, 0, 120, ActStartRecovering},
		{"recovering, ainda dentro", State{Exists: true, Status: StatusFiring, RecoveringSince: tp(0)}, false, 119, 0, 120, ActNone},
		{"recovering, completou", State{Exists: true, Status: StatusFiring, RecoveringSince: tp(0)}, false, 120, 0, 120, ActResolve},
		{"recovering ack, completou", State{Exists: true, Status: StatusAcknowledged, RecoveringSince: tp(0)}, false, 500, 0, 120, ActResolve},
		{"recovering, condição volta (flapping)", State{Exists: true, Status: StatusFiring, RecoveringSince: tp(0)}, true, 60, 0, 120, ActClearRecovering},
	}
	for _, c := range cases {
		if got := Decide(c.st, c.cond, at(c.now), c.dur, c.rec); got != c.want {
			t.Errorf("%s: %v (esperado %v)", c.name, got, c.want)
		}
	}
}

// Simula a vida completa de um alerta, avançando o relógio e aplicando as ações ao estado.
func TestDecideFullLifecycleWithFlapping(t *testing.T) {
	const dur, rec = 120, 60
	var st State
	fired, resolved := 0, 0
	apply := func(a Action, now time.Time) {
		switch a {
		case ActStartPending:
			st = State{Exists: true, Status: StatusPending, PendingSince: &now}
		case ActDropPending:
			st = State{}
		case ActFire:
			st = State{Exists: true, Status: StatusFiring}
			fired++
		case ActStartRecovering:
			st.RecoveringSince = &now
		case ActClearRecovering:
			st.RecoveringSince = nil
		case ActResolve:
			st = State{}
			resolved++
		}
	}
	// condição por segundo: verdadeira 0–59 (curta demais), falsa 60–99, verdadeira 100–499,
	// falsa 500–529 (oscilação curta), verdadeira 530–699, falsa depois.
	cond := func(s int) bool {
		return (s < 60) || (s >= 100 && s < 500) || (s >= 530 && s < 700)
	}
	for s := 0; s <= 900; s += 15 {
		apply(Decide(st, cond(s), at(s), dur, rec), at(s))
	}
	if fired != 1 {
		t.Errorf("deveria disparar exatamente 1 vez (blip inicial descartado, oscilação de 30 s absorvida pela recuperação): %d", fired)
	}
	if resolved != 1 {
		t.Errorf("deveria resolver exatamente 1 vez: %d", resolved)
	}
	if st.Exists {
		t.Errorf("estado final deveria estar limpo: %+v", st)
	}
}

func TestDecideIsIdempotentForSameInput(t *testing.T) {
	st := State{Exists: true, Status: StatusFiring}
	for i := 0; i < 100; i++ {
		if Decide(st, true, at(i), 0, 0) != ActNone {
			t.Fatal("avaliações repetidas com a condição ativa não devem produzir ações")
		}
	}
}
