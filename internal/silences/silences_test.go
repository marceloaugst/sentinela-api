package silences

import (
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestValidate(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		in   CreateInput
		bad  string // campo esperado com problema; vazio = válido
	}{
		{"duração", CreateInput{Reason: "deploy", DurationMinutes: ptr(30)}, ""},
		{"ends_at", CreateInput{Reason: "deploy", EndsAt: ptr(now.Add(time.Hour))}, ""},
		{"agendada", CreateInput{Kind: KindMaintenance, Reason: "x", StartsAt: ptr(now.Add(24 * time.Hour)), DurationMinutes: ptr(60)}, ""},
		{"sem motivo", CreateInput{DurationMinutes: ptr(30)}, "reason"},
		{"kind inválido", CreateInput{Kind: "x", Reason: "r", DurationMinutes: ptr(30)}, "kind"},
		{"sem fim", CreateInput{Reason: "r"}, "ends_at"},
		{"os dois", CreateInput{Reason: "r", DurationMinutes: ptr(5), EndsAt: ptr(now.Add(time.Hour))}, "ends_at"},
		{"duração zero", CreateInput{Reason: "r", DurationMinutes: ptr(0)}, "duration_minutes"},
		{"mais de 30 dias", CreateInput{Reason: "r", DurationMinutes: ptr(31 * 24 * 60)}, "duration_minutes"},
		{"fim no passado", CreateInput{Reason: "r", EndsAt: ptr(now.Add(-time.Minute))}, "ends_at"},
		{"fim antes do início", CreateInput{Reason: "r", StartsAt: ptr(now.Add(2 * time.Hour)), EndsAt: ptr(now.Add(time.Hour))}, "ends_at"},
		{"início muito distante", CreateInput{Reason: "r", StartsAt: ptr(now.Add(100 * 24 * time.Hour)), DurationMinutes: ptr(10)}, "starts_at"},
		{"servidor inválido", CreateInput{Reason: "r", ServerID: ptr("abc"), DurationMinutes: ptr(10)}, "server_id"},
		{"motivo com controle", CreateInput{Reason: "a\x00b", DurationMinutes: ptr(10)}, "reason"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.in.Validate(now)
			if c.bad == "" {
				if len(p) != 0 {
					t.Fatalf("deveria ser válido: %v", p)
				}
				return
			}
			found := false
			for _, x := range p {
				found = found || x.Field == c.bad
			}
			if !found {
				t.Fatalf("esperava problema em %q: %v", c.bad, p)
			}
		})
	}
}

func TestValidateDefaultsAndWindow(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	in := CreateInput{Reason: "  deploy  ", DurationMinutes: ptr(45)}
	if p := in.Validate(now); len(p) != 0 {
		t.Fatal(p)
	}
	if in.Kind != KindSilence || in.Reason != "deploy" || !in.starts.Equal(now) || !in.ends.Equal(now.Add(45*time.Minute)) {
		t.Errorf("normalização: %+v", in)
	}
}
