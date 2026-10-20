package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"sentinela/internal/telemetry"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestLoopRunsImmediatelyRepeatsAndStops(t *testing.T) {
	var n atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Loop(ctx, "t", 20*time.Millisecond, telemetry.NewMetrics(), quiet, func(context.Context) error { n.Add(1); return nil })
		close(done)
	}()
	time.Sleep(110 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop não parou")
	}
	if n.Load() < 3 {
		t.Errorf("execuções: %d", n.Load())
	}
}

func TestLoopSurvivesErrorsAndPanics(t *testing.T) {
	var n atomic.Int32
	m := telemetry.NewMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Loop(ctx, "falha", 10*time.Millisecond, m, quiet, func(context.Context) error {
		switch n.Add(1) {
		case 1:
			panic("boom")
		case 2:
			return errors.New("erro")
		}
		return nil
	})
	time.Sleep(100 * time.Millisecond)
	if n.Load() < 4 {
		t.Errorf("laço deveria continuar após erro e panic: %d execuções", n.Load())
	}
}

func TestLoopNeverOverlaps(t *testing.T) {
	var running, maxRunning atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	Loop(ctx, "slow", 5*time.Millisecond, nil, quiet, func(context.Context) error {
		c := running.Add(1)
		if c > maxRunning.Load() {
			maxRunning.Store(c)
		}
		time.Sleep(30 * time.Millisecond)
		running.Add(-1)
		return nil
	})
	if maxRunning.Load() != 1 {
		t.Errorf("execuções simultâneas: %d", maxRunning.Load())
	}
}
