package metrics

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func sample(sec int, rx, tx int64) NetSample {
	return NetSample{At: t0.Add(time.Duration(sec) * time.Second), RX: rx, TX: tx}
}

func TestCalcRate(t *testing.T) {
	r, ok := CalcRate(sample(0, 1000, 500), sample(10, 3000, 1500))
	if !ok || math.Abs(r.RXBytesPerSec-200) > 1e-9 || math.Abs(r.TXBytesPerSec-100) > 1e-9 {
		t.Errorf("taxa: %+v ok=%v", r, ok)
	}
	if r, ok := CalcRate(sample(0, 5, 5), sample(10, 5, 5)); !ok || r.RXBytesPerSec != 0 {
		t.Errorf("tráfego zero é válido: %+v %v", r, ok)
	}
}

func TestCalcRateRejectsUnreliablePairs(t *testing.T) {
	cases := map[string][2]NetSample{
		"reset de contador rx": {sample(0, 5000, 100), sample(10, 100, 200)},
		"reset de contador tx": {sample(0, 100, 5000), sample(10, 200, 100)},
		"mesmo instante":       {sample(10, 1, 1), sample(10, 2, 2)},
		"tempo retrocedeu":     {sample(10, 1, 1), sample(5, 2, 2)},
		"lacuna grande":        {sample(0, 1, 1), sample(int(MaxSampleGap.Seconds())+1, 2, 2)},
	}
	for name, c := range cases {
		if _, ok := CalcRate(c[0], c[1]); ok {
			t.Errorf("%s: deveria ser inválido", name)
		}
	}
}

func TestRatesSkipsResetAndRecovers(t *testing.T) {
	series := []NetSample{
		sample(0, 0, 0),
		sample(15, 1500, 750), // válido
		sample(30, 100, 50),   // reset: descartado
		sample(45, 1600, 800), // válido de novo
	}
	got := Rates(series)
	if len(got) != 2 {
		t.Fatalf("esperava 2 taxas, obteve %d: %+v", len(got), got)
	}
	if got[0].RXBytesPerSec != 100 || got[1].RXBytesPerSec != 100 {
		t.Errorf("taxas: %+v", got)
	}
	if Rates(nil) == nil || len(Rates(series[:1])) != 0 {
		t.Error("séries curtas devem devolver slice vazio")
	}
}
