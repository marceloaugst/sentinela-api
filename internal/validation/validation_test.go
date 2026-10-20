package validation

import "testing"

func TestText(t *testing.T) {
	var p Problems
	if got := p.Text("n", "  ok  ", 1, 5); got != "ok" || len(p) != 0 {
		t.Errorf("%q %v", got, p)
	}
	for _, v := range []string{"", "   ", "abcdef", "a\x00b"} {
		p = nil
		p.Text("n", v, 1, 5)
		if len(p) != 1 {
			t.Errorf("%q deveria falhar: %v", v, p)
		}
	}
}

func TestHostname(t *testing.T) {
	good := []string{"web-1", "a.b.example.com", "10.0.0.1", "srv_1"}
	bad := []string{"", "-x", "x-", "http://x", "a b", "a/b", "host:22"}
	for _, v := range good {
		var p Problems
		p.Hostname("h", v)
		if len(p) != 0 {
			t.Errorf("%q deveria ser válido: %v", v, p)
		}
	}
	for _, v := range bad {
		var p Problems
		p.Hostname("h", v)
		if len(p) == 0 {
			t.Errorf("%q deveria ser inválido", v)
		}
	}
}
