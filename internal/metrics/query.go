package metrics

import (
	"fmt"
	"time"

	"sentinela/internal/validation"
)

const (
	// MaxPoints é o teto de pontos devolvidos por consulta (protege banco, rede e frontend).
	MaxPoints = 1000
	// MaxRange é o período máximo consultável de uma vez.
	MaxRange = 90 * 24 * time.Hour
	// MaxRawRange: amostras originais só para períodos curtos.
	MaxRawRange  = time.Hour
	DefaultRange = time.Hour
)

// Interval é o tamanho do balde de agregação; Dur == 0 significa amostras originais.
type Interval struct {
	Name string
	Dur  time.Duration
}

var Raw = Interval{Name: "raw"}

// Intervalos de agregação aceitos, do menor para o maior.
var Intervals = []Interval{
	{"1m", time.Minute}, {"5m", 5 * time.Minute}, {"15m", 15 * time.Minute},
	{"1h", time.Hour}, {"6h", 6 * time.Hour}, {"1d", 24 * time.Hour},
}

func (i Interval) IsRaw() bool { return i.Dur == 0 }

type Range struct {
	From, To time.Time // [From, To)
	Interval Interval
}

func parseTime(p *validation.Problems, field, v string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		p.Add(field, "deve estar no formato RFC 3339 (ex.: 2026-03-01T12:00:00Z)")
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ResolveRange valida from/to/interval e escolhe o intervalo automático quando omitido.
// Padrão: última hora. Auto: amostras originais para ≤ 1h (se allowRaw); senão o menor
// balde que mantém o total de pontos ≤ MaxPoints.
func ResolveRange(fromS, toS, intervalS string, now time.Time, allowRaw bool) (Range, validation.Problems) {
	var p validation.Problems
	to := now.UTC()
	if toS != "" {
		if t, ok := parseTime(&p, "to", toS); ok {
			to = t
		}
	}
	from := to.Add(-DefaultRange)
	if fromS != "" {
		if t, ok := parseTime(&p, "from", fromS); ok {
			from = t
		}
	}
	if len(p) > 0 {
		return Range{}, p
	}
	span := to.Sub(from)
	switch {
	case span <= 0:
		p.Add("from", "deve ser anterior a 'to'")
		return Range{}, p
	case span > MaxRange:
		p.Add("from", fmt.Sprintf("período máximo de %d dias", int(MaxRange.Hours()/24)))
		return Range{}, p
	}

	r := Range{From: from, To: to}
	switch intervalS {
	case "":
		if allowRaw && span <= MaxRawRange {
			r.Interval = Raw
			break
		}
		for _, iv := range Intervals {
			if pointsFor(span, iv) <= MaxPoints {
				r.Interval = iv
				break
			}
		}
	case Raw.Name:
		switch {
		case !allowRaw:
			p.Add("interval", "amostras originais não estão disponíveis neste endpoint")
		case span > MaxRawRange:
			p.Add("interval", "'raw' só é permitido para períodos de até 1 hora")
		default:
			r.Interval = Raw
		}
	default:
		found := false
		for _, iv := range Intervals {
			if iv.Name == intervalS {
				found = true
				if pointsFor(span, iv) > MaxPoints {
					p.Add("interval", fmt.Sprintf("geraria mais de %d pontos; use um intervalo maior", MaxPoints))
				}
				r.Interval = iv
			}
		}
		if !found {
			p.Add("interval", "deve ser raw, 1m, 5m, 15m, 1h, 6h ou 1d")
		}
	}
	return r, p
}

func pointsFor(span time.Duration, iv Interval) int {
	if iv.IsRaw() {
		return 0 // o limite de pontos de 'raw' é verificado na consulta
	}
	return int((span + iv.Dur - 1) / iv.Dur)
}
