package svcctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"sentinela/internal/collector"
	"sentinela/internal/svcactions"
)

func TestTargetUnit(t *testing.T) {
	cases := []struct {
		key, unit, want string
		ok              bool
	}{
		{"nginx", "nginx.service", "nginx.service", true},
		{"ssh", "ssh.socket", "ssh.service", true},
		{"docker", "docker.socket", "docker.service", true},
		{"postgresql", "postgresql@16-main.service", "postgresql@16-main.service", true},
		{"postgresql", "postgresql@.service", "", false},
		{"nginx", "sshd.service", "", false},          // unidade de outro serviço
		{"nginx", "nginx.service; reboot", "", false}, // lixo
		{"nginx", "", "", false},
		{"redis", "redis@*", "", false},
		{"inexistente", "nginx.service", "", false},
	}
	for _, c := range cases {
		got, ok := TargetUnit(c.key, c.unit)
		if got != c.want || ok != c.ok {
			t.Errorf("TargetUnit(%q,%q) = %q,%v; esperado %q,%v", c.key, c.unit, got, ok, c.want, c.ok)
		}
	}
}

// fakeHost monta um /sys/fs/cgroup falso com o nginx rodando (e nada mais).
func fakeHost(t *testing.T) *collector.Discoverer {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cgroup", "system.slice", "nginx.service"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"proc", "units"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &collector.Discoverer{CgroupRoot: filepath.Join(root, "cgroup"), ProcRoot: filepath.Join(root, "proc"),
		UnitDirs: []string{filepath.Join(root, "units")}, UFWConf: filepath.Join(root, "ufw.conf")}
}

func TestExecute(t *testing.T) {
	var gotName string
	var gotArgs []string
	var runErr error
	var runOut string
	e := &Executor{Discoverer: fakeHost(t), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return []byte(runOut), runErr
	}}

	st, msg := e.Execute(context.Background(), "nginx", "restart")
	if st != svcactions.StatusSucceeded {
		t.Fatalf("status %s (%s)", st, msg)
	}
	if gotName != "systemctl" || !reflect.DeepEqual(gotArgs, []string{"--no-ask-password", "restart", "nginx.service"}) {
		t.Fatalf("comando inesperado: %s %v", gotName, gotArgs)
	}

	runErr, runOut = errors.New("exit status 1"), "Failed to restart nginx.service: Access denied\n"
	if st, msg = e.Execute(context.Background(), "nginx", "stop"); st != svcactions.StatusFailed || msg != "Failed to restart nginx.service: Access denied" {
		t.Fatalf("falha mal reportada: %s %q", st, msg)
	}

	gotName = ""
	// start de serviço que está rodando, serviço parado/inexistente e ação inválida: nunca chegam ao systemctl.
	for _, c := range [][2]string{{"nginx", "start"}, {"redis", "restart"}, {"nginx", "disable"}, {"foo", "stop"}} {
		if st, _ := e.Execute(context.Background(), c[0], c[1]); st != svcactions.StatusFailed {
			t.Errorf("%v deveria falhar", c)
		}
	}
	if gotName != "" {
		t.Fatalf("systemctl não deveria ter sido chamado: %s", gotName)
	}
}
