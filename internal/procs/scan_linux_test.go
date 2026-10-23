//go:build linux

package procs

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestScanSelf(t *testing.T) {
	s := NewScanner()
	s.Scan(time.Now())
	time.Sleep(1100 * time.Millisecond)
	rep := s.Scan(time.Now())
	if rep.CPUs < 1 || rep.MemoryTotalBytes <= 0 || rep.Total < 1 {
		t.Fatalf("relatório: cpus=%d mem=%d total=%d", rep.CPUs, rep.MemoryTotalBytes, rep.Total)
	}
	if p := rep.Validate(time.Now()); len(p) > 0 {
		t.Fatalf("o relatório real não passa na validação: %v", p)
	}
	var self *Process
	for i := range rep.Processes {
		if rep.Processes[i].PID == os.Getpid() {
			self = &rep.Processes[i]
		}
		if rep.Processes[i].PID == 2 {
			t.Error("thread de kernel na lista")
		}
	}
	if self == nil {
		t.Fatal("o próprio processo não está na lista")
	}
	if self.Restriction != RestrictSelf || self.MemoryBytes <= 0 || self.StartTime == 0 || self.User == "" {
		t.Errorf("self: %+v", *self)
	}
}

// Um filho do mesmo usuário é encerrável e some depois do SIGTERM; o pid reaproveitado/inexistente e os
// restritos são recusados.
func TestTerminate(t *testing.T) {
	s := NewScanner()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("sem sleep:", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }() // colhe o zumbi
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	p, ok := s.Inspect(cmd.Process.Pid)
	if !ok || p.Restriction != RestrictNone || p.Name != "sleep" || !strings.Contains(p.Cmdline, "sleep 60") {
		t.Fatalf("filho: ok=%v %+v", ok, p)
	}
	start := s.startOf(cmd.Process.Pid)
	ctx := context.Background()

	// início diferente = outro processo com o mesmo pid: não toca
	if ok, msg := s.Terminate(ctx, Target(cmd.Process.Pid, start+1), ActionTerminate); ok {
		t.Fatalf("início errado foi aceito: %s", msg)
	}
	if ok, msg := s.Terminate(ctx, Target(os.Getpid(), s.startOf(os.Getpid())), ActionKill); ok {
		t.Fatalf("o próprio processo foi aceito: %s", msg)
	}
	if ok, _ := s.Terminate(ctx, "1:1", ActionKill); ok {
		t.Fatal("pid 1 aceito")
	}
	if ok, _ := s.Terminate(ctx, Target(cmd.Process.Pid, start), "reboot"); ok {
		t.Fatal("ação inválida aceita")
	}
	select {
	case <-done:
		t.Fatal("o filho morreu sem pedido")
	default:
	}

	ok, msg := s.Terminate(ctx, Target(cmd.Process.Pid, start), ActionTerminate)
	if !ok {
		t.Fatalf("terminate: %s", msg)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("o filho continua vivo")
	}
	// já foi: resposta clara, sem erro estranho
	if ok, msg := s.Terminate(ctx, Target(cmd.Process.Pid, start), ActionTerminate); ok || !strings.Contains(msg, "não existe") {
		t.Errorf("depois de encerrado: %v %q", ok, msg)
	}
}

func TestKillIgnoresSigterm(t *testing.T) {
	s := NewScanner()
	cmd := exec.Command("sh", "-c", `trap '' TERM; echo ready; while :; do sleep 1; done`)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	go func() { _ = cmd.Wait() }()
	buf := make([]byte, 6)
	_, _ = out.Read(buf) // espera o trap valer
	pid := cmd.Process.Pid
	target := Target(pid, s.startOf(pid))
	ctx := context.Background()
	if ok, msg := s.Terminate(ctx, target, ActionTerminate); ok || !strings.Contains(msg, "SIGTERM") {
		t.Fatalf("SIGTERM ignorado deveria falhar com dica: %v %q", ok, msg)
	}
	if ok, msg := s.Terminate(ctx, target, ActionKill); !ok {
		t.Fatalf("kill: %s", msg)
	}
}
