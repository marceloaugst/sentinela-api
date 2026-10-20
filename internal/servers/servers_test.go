package servers

import "testing"

func ptr(s string) *string { return &s }

func TestCreateInputValidate(t *testing.T) {
	in := CreateInput{Name: "  web-1 ", Hostname: "web-1.example.com"}
	if p := in.Validate(); len(p) != 0 || in.Name != "web-1" {
		t.Errorf("válido: %v %q", p, in.Name)
	}
	bad := CreateInput{Name: "", Hostname: "http://x"}
	if p := bad.Validate(); len(p) != 2 {
		t.Errorf("esperava 2 problemas: %v", p)
	}
}

func TestUpdateInputValidate(t *testing.T) {
	empty := UpdateInput{}
	if p := empty.Validate(); len(p) != 1 {
		t.Errorf("patch vazio deveria falhar: %v", p)
	}
	ok := UpdateInput{Status: ptr(StatusMaintenance)}
	if p := ok.Validate(); len(p) != 0 {
		t.Errorf("status válido: %v", p)
	}
	bad := UpdateInput{Status: ptr("online"), Name: ptr(" ")}
	if p := bad.Validate(); len(p) != 2 {
		t.Errorf("esperava 2 problemas: %v", p)
	}
}

func TestEscapeLike(t *testing.T) {
	if got := escapeLike(`50%_a\b`); got != `50\%\_a\\b` {
		t.Errorf("escapeLike = %q", got)
	}
}

func TestSortAllowed(t *testing.T) {
	if !SortAllowed("name") || SortAllowed("password; DROP TABLE") {
		t.Error("lista de ordenação permitida incorreta")
	}
}
