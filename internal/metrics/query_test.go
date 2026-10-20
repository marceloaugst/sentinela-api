package metrics

import (
	"strings"
	"testing"
	"time"
)

var qNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func resolve(from, to, iv string, raw bool) (Range, string) {
	r, p := ResolveRange(from, to, iv, qNow, raw)
	var sb strings.Builder
	for _, x := range p {
		sb.WriteString(x.Field + ";")
	}
	return r, sb.String()
}

func TestResolveRangeDefaults(t *testing.T) {
	r, errs := resolve("", "", "", true)
	if errs != "" || !r.To.Equal(qNow) || r.To.Sub(r.From) != time.Hour || !r.Interval.IsRaw() {
		t.Errorf("padrão: %+v %q", r, errs)
	}
	// sem raw (dashboard) o auto começa em 1m
	r, _ = resolve("", "", "", false)
	if r.Interval.Name != "1m" {
		t.Errorf("auto sem raw: %v", r.Interval)
	}
}

func TestResolveRangeAutoPicksSmallestBucketUnderLimit(t *testing.T) {
	cases := []struct {
		span time.Duration
		want string
	}{
		{30 * time.Minute, "raw"},
		{time.Hour, "raw"},
		{2 * time.Hour, "1m"},
		{16 * time.Hour, "1m"},      // 960 pontos
		{17 * time.Hour, "5m"},      // 1m daria 1020
		{3 * 24 * time.Hour, "5m"},  // 864 pontos
		{7 * 24 * time.Hour, "15m"}, // 672 pontos
		{30 * 24 * time.Hour, "1h"}, // 720 pontos
		{90 * 24 * time.Hour, "6h"}, // 360 pontos (1h daria 2160)
	}
	for _, c := range cases {
		r, errs := resolve(qNow.Add(-c.span).Format(time.RFC3339), "", "", true)
		if errs != "" || r.Interval.Name != c.want {
			t.Errorf("span %v: intervalo %q (esperado %q) %q", c.span, r.Interval.Name, c.want, errs)
		}
		if n := pointsFor(c.span, r.Interval); !r.Interval.IsRaw() && n > MaxPoints {
			t.Errorf("span %v gerou %d pontos", c.span, n)
		}
	}
}

func TestResolveRangeErrors(t *testing.T) {
	day := func(n int) string { return qNow.Add(-time.Duration(n) * 24 * time.Hour).Format(time.RFC3339) }
	cases := []struct {
		name, from, to, iv string
		raw                bool
		field              string
	}{
		{"from inválido", "ontem", "", "", true, "from"},
		{"to inválido", "", "x", "", true, "to"},
		{"from >= to", qNow.Format(time.RFC3339), qNow.Format(time.RFC3339), "", true, "from"},
		{"período > 90d", day(91), "", "", true, "from"},
		{"intervalo desconhecido", "", "", "2m", true, "interval"},
		{"raw em período longo", day(1), "", "raw", true, "interval"},
		{"raw proibido", "", "", "raw", false, "interval"},
		{"pontos demais", day(30), "", "1m", true, "interval"},
	}
	for _, c := range cases {
		_, errs := resolve(c.from, c.to, c.iv, c.raw)
		if !strings.Contains(errs, c.field+";") {
			t.Errorf("%s: esperava erro em %q, obteve %q", c.name, c.field, errs)
		}
	}
}

func TestResolveRangeExplicitValid(t *testing.T) {
	r, errs := resolve(qNow.Add(-24*time.Hour).Format(time.RFC3339), qNow.Format(time.RFC3339), "5m", true)
	if errs != "" || r.Interval.Name != "5m" || r.To.Sub(r.From) != 24*time.Hour {
		t.Errorf("%+v %q", r, errs)
	}
	// fuso é normalizado para UTC
	r, _ = resolve("2026-03-01T09:00:00-03:00", "2026-03-01T09:30:00-03:00", "", true)
	if r.From.Location() != time.UTC || !r.From.Equal(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("from: %v", r.From)
	}
}
