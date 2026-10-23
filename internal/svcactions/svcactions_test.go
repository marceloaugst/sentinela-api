package svcactions

import (
	"reflect"
	"strings"
	"testing"

	"sentinela/internal/discovery"
)

func TestAllowed(t *testing.T) {
	cases := []struct {
		name                      string
		key, status, source, unit string
		want                      []string
	}{
		{"nginx rodando", "nginx", discovery.StatusAvailable, discovery.SourceSystemd, "nginx.service", []string{"stop", "restart"}},
		{"nginx parado", "nginx", discovery.StatusStopped, "", "nginx.service", []string{"start"}},
		{"ssh nunca para", "ssh", discovery.StatusAvailable, discovery.SourceSystemd, "ssh.service", []string{"restart"}},
		{"container docker não", "redis", discovery.StatusAvailable, discovery.SourceDocker, "", nil},
		{"processo solto não", "redis", discovery.StatusAvailable, discovery.SourceProcess, "redis-server.service", nil},
		{"não instalado", "nginx", discovery.StatusNotFound, "", "", nil},
		{"journald fora", "journald", discovery.StatusAvailable, discovery.SourceSystemd, "systemd-journald.service", nil},
		{"ufw fora", "ufw", discovery.StatusStopped, "", "ufw.service", nil},
		{"sem unidade", "nginx", discovery.StatusStopped, "", "", nil},
	}
	for _, c := range cases {
		if got := Allowed(c.key, c.status, c.source, c.unit); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, esperado %v", c.name, got, c.want)
		}
	}
}

func TestControllableKeysExistInCatalog(t *testing.T) {
	for k := range controllable {
		if _, ok := discovery.Lookup(k); !ok {
			t.Errorf("%q não está no catálogo", k)
		}
	}
}

func TestResultValidate(t *testing.T) {
	r := Result{Status: "ok"}
	if len(r.Validate()) == 0 {
		t.Fatal("status inválido deveria ser recusado")
	}
	r = Result{Status: StatusFailed, Message: "x\n\x00" + strings.Repeat("a", 500)}
	if p := r.Validate(); len(p) != 0 {
		t.Fatal(p)
	}
	if len([]rune(r.Message)) != 300 || strings.ContainsAny(r.Message, "\n\x00") {
		t.Fatalf("mensagem não sanitizada: %q", r.Message)
	}
}
