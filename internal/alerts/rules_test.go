package alerts

import (
	"strings"
	"testing"
)

func TestCatalogIsConsistent(t *testing.T) {
	codes := map[string]bool{}
	for _, s := range Catalog {
		if s.Code == "" || s.Name == "" || s.Description == "" || codes[s.Code] {
			t.Errorf("regra inválida ou duplicada: %+v", s)
		}
		codes[s.Code] = true
		if !operatorOK(s.Operator) {
			t.Errorf("%s: operador %q", s.Code, s.Operator)
		}
		if s.Priority < P1 || s.Priority > P4 {
			t.Errorf("%s: prioridade %d", s.Code, s.Priority)
		}
		if s.Duration < 0 || s.Recovery < 0 {
			t.Errorf("%s: tempos negativos", s.Code)
		}
		switch s.Metric {
		case MetricCPU, MetricMemory, MetricDisk, MetricLoad, MetricLoadPerCPU, MetricOffline, MetricServiceDown, MetricSwap,
			MetricOOM, MetricInodes, MetricDiskLatency, MetricNTP, MetricUpdates, MetricCert:
		default:
			t.Errorf("%s: métrica %q", s.Code, s.Metric)
		}
	}
}

func operatorOK(op string) bool {
	switch op {
	case ">", ">=", "<", "<=", "==":
		return true
	}
	return false
}

func TestSeverityOf(t *testing.T) {
	for p, want := range map[int]string{P1: "critical", P2: "critical", P3: "warning", P4: "info", 0: "info"} {
		if got := SeverityOf(p); got != want {
			t.Errorf("P%d = %s, esperado %s", p, got, want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		op   string
		v, t float64
		want bool
	}{
		{">", 91, 90, true}, {">", 90, 90, false}, {">=", 90, 90, true}, {"<", 5, 10, true}, {"<", 10, 10, false},
		{"<=", 10, 10, true}, {"==", 1, 1, true}, {"==", 0, 1, false}, {"?", 1, 1, false},
	}
	for _, c := range cases {
		if Compare(c.op, c.v, c.t) != c.want {
			t.Errorf("%v %s %v", c.v, c.op, c.t)
		}
	}
}

func TestMessage(t *testing.T) {
	r := Rule{MetricName: MetricCPU, Operator: ">", Threshold: 90}
	if got := Message(r, 93.24, ""); got != "Uso de CPU em 93.2% (limite: > 90%)" {
		t.Error(got)
	}
	r = Rule{MetricName: MetricDisk, Operator: ">=", Threshold: 85.5}
	if got := Message(r, 91.0, "/data"); !strings.Contains(got, "/data") || !strings.Contains(got, "85.5") {
		t.Error(got)
	}
	r = Rule{MetricName: MetricOffline, Operator: ">", Threshold: 120}
	if got := Message(r, 200, ""); got != "Sem comunicação há 3 min 20 s (limite: > 2 min 0 s)" {
		t.Error(got)
	}
	r = Rule{MetricName: MetricServiceDown}
	if got := Message(r, 1, `"api": tempo limite excedido`); !strings.HasPrefix(got, "Serviço indisponível: ") {
		t.Error(got)
	}
	r = Rule{MetricName: MetricSwap, Operator: ">", Threshold: 50}
	if got := Message(r, 72.34, ""); got != "Uso de swap em 72.3% (limite: > 50%)" {
		t.Error(got)
	}
	if humanDuration(7260) != "2 h 1 min" || humanDuration(5) != "5 s" {
		t.Error("humanDuration")
	}
}
