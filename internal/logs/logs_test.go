package logs

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func good() Entry {
	return Entry{Time: now.Add(-time.Minute), Source: SourceNginx, Type: TypeAccess, Severity: SevInfo, IP: "203.0.113.9"}
}

func TestClean(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"GET /x\x1b[31m\r\nINJETADO", 100, "GET /x[31mINJETADO"},
		{"a\tb", 10, "a b"},
		{"abcdef", 3, "abc"},
		{"ação", 3, "açã"}, // limite em runas, não em bytes
		{"\xff\xfeok", 10, "�ok"},
	}
	for _, c := range cases {
		if got := Clean(c.in, c.n); got != c.want {
			t.Errorf("Clean(%q,%d) = %q, quer %q", c.in, c.n, got, c.want)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9": "203.0.113.9", "::ffff:203.0.113.9": "203.0.113.9", "2001:DB8::1": "2001:db8::1", " 1.2.3.4 ": "1.2.3.4",
		"fe80::1%eth0": "fe80::1",
	} {
		if got, ok := NormalizeIP(in); !ok || got != want {
			t.Errorf("NormalizeIP(%q) = %q,%v; quer %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abc", "1.2.3", "1.2.3.4/24", "999.1.1.1"} {
		if _, ok := NormalizeIP(in); ok {
			t.Errorf("%q deveria ser inválido", in)
		}
	}
}

func TestBatchValidate(t *testing.T) {
	b := Batch{BatchID: "lote-0001-abcd", Entries: []Entry{good()}}
	if p := b.Validate(now); len(p) != 0 {
		t.Fatalf("lote válido rejeitado: %+v", p)
	}

	mut := func(f func(e *Entry)) Batch {
		e := good()
		f(&e)
		return Batch{BatchID: "lote-0001-abcd", Entries: []Entry{e}}
	}
	bad := map[string]Batch{
		"batch_id":  {BatchID: "x", Entries: []Entry{good()}},
		"vazio":     {BatchID: "lote-0001-abcd"},
		"fonte":     mut(func(e *Entry) { e.Source = "apache" }),
		"tipo":      mut(func(e *Entry) { e.Type = TypeBan }),
		"gravidade": mut(func(e *Entry) { e.Severity = "fatal" }),
		"ip":        mut(func(e *Entry) { e.IP = "nao-e-ip" }),
		"porta":     mut(func(e *Entry) { e.Port = 70000 }),
		"status":    mut(func(e *Entry) { e.Status = 99 }),
		"futuro":    mut(func(e *Entry) { e.Time = now.Add(time.Hour) }),
		"antigo":    mut(func(e *Entry) { e.Time = now.AddDate(0, 0, -31) }),
		"zero":      mut(func(e *Entry) { e.Time = time.Time{} }),
		"chave":     mut(func(e *Entry) { e.Fields = map[string]string{"Chave Ruim": "x"} }),
	}
	for name, b := range bad {
		if p := b.Validate(now); len(p) == 0 {
			t.Errorf("%s: deveria ser rejeitado", name)
		}
	}

	many := Batch{BatchID: "lote-0001-abcd", Entries: make([]Entry, MaxBatchEntries+1)}
	if p := many.Validate(now); len(p) == 0 {
		t.Error("lote acima do limite deveria ser rejeitado")
	}
}

func TestBatchValidateSanitizesInPlace(t *testing.T) {
	e := good()
	e.IP = "::ffff:203.0.113.9"
	e.Raw = "linha\x00com\x1bcontrole\n" + strings.Repeat("x", 5000)
	e.Fields = map[string]string{"path": "/a\r\nb", "ua": strings.Repeat("u", 1000)}
	b := Batch{BatchID: "lote-0001-abcd", Entries: []Entry{e}}
	if p := b.Validate(now); len(p) != 0 {
		t.Fatalf("%+v", p)
	}
	got := b.Entries[0]
	if got.IP != "203.0.113.9" {
		t.Errorf("ip: %q", got.IP)
	}
	if strings.ContainsAny(got.Raw, "\x00\x1b\n") || len([]rune(got.Raw)) != MaxRawLen {
		t.Errorf("raw não saneado: %d runas", len([]rune(got.Raw)))
	}
	if got.Fields["path"] != "/ab" || len([]rune(got.Fields["ua"])) != MaxFieldValue {
		t.Errorf("fields não saneados: %+v", got.Fields)
	}
}
