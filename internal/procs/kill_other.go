//go:build !linux

package procs

import "context"

// Terminate só existe no Linux.
func (s *Scanner) Terminate(ctx context.Context, target, action string) (bool, string) {
	return false, "Encerrar processos só é suportado no Linux."
}
