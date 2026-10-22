package sysmetrics

import (
	"math"
	"testing"
	"time"
)

func TestBatchValidate(t *testing.T) {
	now := time.Now()
	ok := Batch{BatchID: "lote-1234", Samples: []Sample{{Time: now, Metric: OOMKills, Value: 1}, {Time: now, Metric: InodeUsed, Subject: " /var\n", Value: 40}}}
	if p := ok.Validate(now); len(p) != 0 || ok.Samples[1].Subject != "/var" {
		t.Errorf("%v %+v", p, ok.Samples)
	}
	bad := map[string]Batch{
		"batch_id":    {BatchID: "x", Samples: []Sample{{Time: now, Metric: OOMKills}}},
		"vazio":       {BatchID: "lote-1234"},
		"métrica":     {BatchID: "lote-1234", Samples: []Sample{{Time: now, Metric: "rm -rf"}}},
		"NaN":         {BatchID: "lote-1234", Samples: []Sample{{Time: now, Metric: OOMKills, Value: math.NaN()}}},
		"futuro":      {BatchID: "lote-1234", Samples: []Sample{{Time: now.Add(time.Hour), Metric: OOMKills}}},
		"antigo":      {BatchID: "lote-1234", Samples: []Sample{{Time: now.Add(-2 * time.Hour), Metric: OOMKills}}},
		"sem horário": {BatchID: "lote-1234", Samples: []Sample{{Metric: OOMKills}}},
	}
	for name, b := range bad {
		if p := b.Validate(now); len(p) == 0 {
			t.Errorf("%s deveria falhar", name)
		}
	}
}
