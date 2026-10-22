package discovery

import (
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	now := time.Now()
	ok := Report{CheckedAt: now, Services: []Finding{
		{Key: "ssh", Status: StatusAvailable, Source: SourceSystemd, Unit: "ssh.service"},
		{Key: "redis", Status: StatusNotFound},
	}}
	if p := ok.Validate(now); len(p) > 0 {
		t.Fatalf("relatório válido recusado: %v", p)
	}
	bad := []Report{
		{CheckedAt: now},
		{CheckedAt: now, Services: []Finding{{Key: "mysql", Status: StatusNotFound}}},
		{CheckedAt: now, Services: []Finding{{Key: "ssh", Status: "ok"}}},
		{CheckedAt: now, Services: []Finding{{Key: "ssh", Status: StatusAvailable}}},
		{CheckedAt: now, Services: []Finding{{Key: "ssh", Status: StatusNotFound, Source: SourceDocker}}},
		{CheckedAt: now, Services: []Finding{{Key: "ssh", Status: StatusAvailable, Source: "x"}}},
		{CheckedAt: now, Services: []Finding{{Key: "ssh", Status: StatusStopped, Unit: "a b;rm"}}},
		{CheckedAt: now, Services: []Finding{{Key: "ssh", Status: StatusNotFound}, {Key: "ssh", Status: StatusNotFound}}},
		{CheckedAt: now.Add(-2 * time.Hour), Services: []Finding{{Key: "ssh", Status: StatusNotFound}}},
	}
	for i, r := range bad {
		if p := r.Validate(now); len(p) == 0 {
			t.Errorf("caso %d: esperava erro de validação", i)
		}
	}
}

func TestActionAndSummary(t *testing.T) {
	now := time.Now()
	items := []Item{
		NewItem("ssh", StatusAvailable, SourceSystemd, "ssh.service", now, nil),
		NewItem("nginx", StatusStopped, "", "nginx.service", now, nil),
		NewItem("redis", StatusNotFound, "", "", now, nil),
	}
	if items[0].Action != "" || !items[0].Available {
		t.Errorf("ssh disponível não deve ter ação: %+v", items[0])
	}
	if !strings.Contains(items[1].Action, "systemctl enable --now nginx.service") {
		t.Errorf("ação do nginx: %q", items[1].Action)
	}
	if !strings.Contains(items[2].Action, "docker run") {
		t.Errorf("ação do redis deve citar o Docker: %q", items[2].Action)
	}
	if s := Summarize(items); s.Total != 3 || s.Available != 1 || s.Unavailable != 2 {
		t.Errorf("resumo: %+v", s)
	}
	for _, spec := range Catalog {
		for _, st := range []string{StatusStopped, StatusNotFound} {
			if Action(spec.Key, st, "") == "" {
				t.Errorf("%s/%s sem ação", spec.Key, st)
			}
		}
	}
}
