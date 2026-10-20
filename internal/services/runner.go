package services

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Runner verifica periodicamente os serviços http vencidos, com concorrência limitada.
type Runner struct {
	Repo    *Repository
	Checker *Checker
	Log     *slog.Logger
	Workers int // verificações simultâneas
	Batch   int // serviços reservados por ciclo
	Now     func() time.Time
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Tick reserva e executa as verificações vencidas. Devolve quantas foram executadas.
func (r *Runner) Tick(ctx context.Context) error {
	_, err := r.RunDue(ctx)
	return err
}

func (r *Runner) RunDue(ctx context.Context) (int, error) {
	batch := r.Batch
	if batch <= 0 {
		batch = 50
	}
	due, err := r.Repo.ClaimDue(ctx, batch)
	if err != nil {
		return 0, err
	}
	workers := r.Workers
	if workers <= 0 {
		workers = 8
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, s := range due {
		sem <- struct{}{}
		wg.Add(1)
		go func(s Service) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := r.CheckOne(ctx, s); err != nil && ctx.Err() == nil {
				r.Log.Error("falha ao gravar resultado da verificação", "service_id", s.ID, "err", err)
			}
		}(s)
	}
	wg.Wait()
	return len(due), nil
}

// CheckOne executa e grava a verificação de um serviço http.
func (r *Runner) CheckOne(ctx context.Context, s Service) (Result, error) {
	if s.Type != TypeHTTP {
		return Result{}, ErrNotCentral
	}
	res := r.Checker.Check(ctx, s.Target, s.Config)
	_, err := r.Repo.RecordResult(ctx, s.ID, nil, res, r.now().UTC())
	return res, err
}
