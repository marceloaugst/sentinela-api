package alerts

import (
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }
func sp(s string) *string  { return &s }

func probs(in CreateRuleInput) string {
	_, p := in.Validate()
	var sb strings.Builder
	for _, x := range p {
		sb.WriteString(x.Field + ";")
	}
	return sb.String()
}

func valid() CreateRuleInput {
	return CreateRuleInput{Name: "CPU alta", MetricName: MetricCPU, Operator: ">", Threshold: f(90), Severity: "critical", DurationSeconds: 120}
}

func TestCreateRuleValid(t *testing.T) {
	in := valid()
	r, p := in.Validate()
	if len(p) != 0 || !r.IsEnabled || r.ServerID != nil {
		t.Errorf("%v %+v", p, r)
	}
	off := false
	in.IsEnabled = &off
	if r, _ := in.Validate(); r.IsEnabled {
		t.Error("is_enabled=false deveria ser respeitado")
	}
}

func TestCreateRuleExamplesFromSpec(t *testing.T) {
	for name, in := range map[string]CreateRuleInput{
		"CPU > 90":        {Name: "a", MetricName: MetricCPU, Operator: ">", Threshold: f(90), Severity: "warning"},
		"RAM > 90":        {Name: "b", MetricName: MetricMemory, Operator: ">", Threshold: f(90), Severity: "warning"},
		"disco > 85":      {Name: "c", MetricName: MetricDisk, Operator: ">", Threshold: f(85), Severity: "critical", RecoverySeconds: 300},
		"sem comunicação": {Name: "d", MetricName: MetricOffline, Operator: ">", Threshold: f(120), Severity: "critical"},
		"serviço down":    {Name: "e", MetricName: MetricServiceDown, Operator: "==", Threshold: f(1), Severity: "critical"},
		"load":            {Name: "g", MetricName: MetricLoad, Operator: ">=", Threshold: f(4), Severity: "info"},
	} {
		if got := probs(in); got != "" {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestCreateRuleRejections(t *testing.T) {
	mut := func(fn func(*CreateRuleInput)) CreateRuleInput { in := valid(); fn(&in); return in }
	cases := map[string]struct {
		in    CreateRuleInput
		field string
	}{
		"sem nome":            {mut(func(i *CreateRuleInput) { i.Name = " " }), "name"},
		"métrica inválida":    {mut(func(i *CreateRuleInput) { i.MetricName = "uptime" }), "metric_name"},
		"operador inválido":   {mut(func(i *CreateRuleInput) { i.Operator = "!=" }), "operator"},
		"severidade inválida": {mut(func(i *CreateRuleInput) { i.Severity = "fatal" }), "severity"},
		"sem threshold":       {mut(func(i *CreateRuleInput) { i.Threshold = nil }), "threshold"},
		"cpu > 100":           {mut(func(i *CreateRuleInput) { i.Threshold = f(150) }), "threshold"},
		"cpu negativa":        {mut(func(i *CreateRuleInput) { i.Threshold = f(-1) }), "threshold"},
		"duração negativa":    {mut(func(i *CreateRuleInput) { i.DurationSeconds = -1 }), "duration_seconds"},
		"duração enorme":      {mut(func(i *CreateRuleInput) { i.DurationSeconds = 999999 }), "duration_seconds"},
		"recuperação enorme":  {mut(func(i *CreateRuleInput) { i.RecoverySeconds = 999999 }), "recovery_seconds"},
		"server_id inválido":  {mut(func(i *CreateRuleInput) { i.ServerID = sp("xyz") }), "server_id"},
		"offline com <":       {CreateRuleInput{Name: "x", MetricName: MetricOffline, Operator: "<", Threshold: f(60), Severity: "info"}, "operator"},
		"offline threshold 0": {CreateRuleInput{Name: "x", MetricName: MetricOffline, Operator: ">", Threshold: f(0), Severity: "info"}, "threshold"},
		"service_down com >":  {CreateRuleInput{Name: "x", MetricName: MetricServiceDown, Operator: ">", Threshold: f(1), Severity: "info"}, "operator"},
		"service_down th 5":   {CreateRuleInput{Name: "x", MetricName: MetricServiceDown, Operator: "==", Threshold: f(5), Severity: "info"}, "operator"},
	}
	for name, c := range cases {
		if got := probs(c.in); !strings.Contains(got, c.field+";") {
			t.Errorf("%s: esperava erro em %q, obteve %q", name, c.field, got)
		}
	}
}

func TestUpdateRuleMergesAndRevalidates(t *testing.T) {
	cur := Rule{Name: "r", MetricName: MetricCPU, Operator: ">", Threshold: 90, Severity: "critical"}
	if _, p := (&UpdateRuleInput{}).Validate(cur); len(p) != 1 {
		t.Errorf("patch vazio: %v", p)
	}
	r, p := (&UpdateRuleInput{Threshold: f(80), Severity: sp("warning")}).Validate(cur)
	if len(p) != 0 || r.Threshold != 80 || r.Severity != "warning" || r.Name != "r" {
		t.Errorf("merge: %v %+v", p, r)
	}
	// trocar a métrica revalida o conjunto: threshold 90 não vale para service_down
	if _, p := (&UpdateRuleInput{MetricName: sp(MetricServiceDown)}).Validate(cur); len(p) == 0 {
		t.Error("trocar para service_down mantendo > 90 deveria falhar")
	}
	en := false
	if r, p := (&UpdateRuleInput{IsEnabled: &en}).Validate(cur); len(p) != 0 || r.IsEnabled {
		t.Errorf("desativar: %v", p)
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
	if humanDuration(7260) != "2 h 1 min" || humanDuration(5) != "5 s" {
		t.Error("humanDuration")
	}
}
