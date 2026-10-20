package metrics

import (
	"math"
	"testing"
	"time"
)

func TestAvailability(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }
	timeout := 60 * time.Second
	near := func(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

	cases := []struct {
		name     string
		times    []time.Time
		from, to time.Time
		want     float64
	}{
		{"sem amostras", nil, at(0), at(600), 0},
		{"comunicação contínua", times(at, 0, 15, 600), at(0), at(600), 100},
		{"uma amostra cobre só o timeout", []time.Time{at(0)}, at(0), at(600), 10},
		{"lacuna de 5 min no meio", append(times(at, 0, 15, 120), times(at, 420, 15, 600)...), at(0), at(600), 345.0 / 600 * 100},
		{"amostra anterior à janela cobre o início", []time.Time{at(-30)}, at(0), at(600), 5},
		{"amostra posterior ao fim é ignorada", []time.Time{at(700)}, at(0), at(600), 0},
		{"janela vazia", []time.Time{at(0)}, at(10), at(10), 0},
	}
	for _, c := range cases {
		got := Availability(c.times, c.from, c.to, timeout)
		if !near(got, c.want) {
			t.Errorf("%s: %.4f (esperado %.4f)", c.name, got, c.want)
		}
	}
	if Availability([]time.Time{at(0)}, at(0), at(10), 0) != 0 {
		t.Error("timeout inválido deve resultar em 0")
	}
}

// times gera amostras de start até end (exclusive) a cada step segundos.
func times(at func(int) time.Time, start, step, end int) []time.Time {
	var out []time.Time
	for s := start; s < end; s += step {
		out = append(out, at(s))
	}
	return out
}
