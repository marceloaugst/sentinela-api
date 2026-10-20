// Package scheduler executa tarefas periódicas em segundo plano com medição e isolamento de falhas.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"sentinela/internal/telemetry"
)

// Loop executa fn imediatamente e depois a cada `every`, sem sobreposição (uma execução por vez),
// até o contexto terminar. Erros e panics são registrados e não encerram o laço.
func Loop(ctx context.Context, name string, every time.Duration, m *telemetry.Metrics, log *slog.Logger, fn func(context.Context) error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		runOnce(ctx, name, m, log, fn)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func runOnce(ctx context.Context, name string, m *telemetry.Metrics, log *slog.Logger, fn func(context.Context) error) {
	start := time.Now()
	result := "ok"
	defer func() {
		if r := recover(); r != nil {
			result = "panic"
			log.Error("tarefa com panic", "job", name, "panic", fmt.Sprint(r))
		}
		if m != nil {
			m.JobDuration.WithLabelValues(name, result).Observe(time.Since(start).Seconds())
		}
	}()
	if err := fn(ctx); err != nil && ctx.Err() == nil {
		result = "error"
		log.Error("tarefa falhou", "job", name, "err", err)
	}
}
