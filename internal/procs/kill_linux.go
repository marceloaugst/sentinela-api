//go:build linux

package procs

import (
	"context"
	"errors"
	"syscall"
	"time"
)

// Terminate encerra o processo (pid, início) se ele passar pelas MESMAS regras da listagem. A ordem evita corrida com
// reaproveitamento de pid: 1) abre um pidfd, que prende o processo; 2) confere em /proc que ele é o processo pedido
// (mesmo início) e que não tem restrição; 3) sinaliza pelo pidfd, que nunca atinge outro processo.
// Devolve (ok, mensagem para a tela).
func (s *Scanner) Terminate(ctx context.Context, target, action string) (bool, string) {
	pid, start, ok := ParseTarget(target)
	if !ok || !ValidAction(action) {
		return false, "processo ou ação inválidos"
	}
	fd, err := pidfdOpen(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return false, "O processo não existe mais."
		}
		return false, "Não foi possível acessar o processo: " + err.Error()
	}
	defer syscall.Close(fd)

	p, found := s.Inspect(pid)
	if !found || s.startOf(pid) != start {
		return false, "O processo não existe mais (o pid pode ter sido reaproveitado por outro)."
	}
	if p.Restriction != RestrictNone {
		return false, RestrictionText(p.Restriction)
	}
	sig, wait, label := syscall.SIGTERM, 5*time.Second, "SIGTERM"
	if action == ActionKill {
		sig, wait, label = syscall.SIGKILL, 3*time.Second, "SIGKILL"
	}
	if err := pidfdSendSignal(fd, sig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return true, "O processo já tinha terminado."
		}
		return false, "Falha ao enviar " + label + ": " + err.Error()
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if s.gone(pid, start) {
			return true, p.Name + " (pid " + itoa(pid) + ") encerrado com " + label + "."
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			if action == ActionTerminate {
				return false, p.Name + " recebeu SIGTERM mas continua ativo; se precisar, use Forçar (SIGKILL)."
			}
			return false, p.Name + " recebeu SIGKILL mas continua ativo (talvez bloqueado em E/S do kernel)."
		case <-ctx.Done():
			return false, "Cancelado antes de confirmar o encerramento."
		}
	}
}

// pidfd_open (434) e pidfd_send_signal (424) têm o mesmo número em todas as arquiteturas modernas.
func pidfdOpen(pid int) (int, error) {
	fd, _, e := syscall.Syscall(434, uintptr(pid), 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

func pidfdSendSignal(fd int, sig syscall.Signal) error {
	_, _, e := syscall.Syscall6(424, uintptr(fd), uintptr(sig), 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
