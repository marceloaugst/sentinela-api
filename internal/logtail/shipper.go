package logtail

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"sentinela/internal/agentclient"
	"sentinela/internal/logs"
)

// Sender envia um lote à API. *agentclient.Client satisfaz via Do.
type Sender interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// Shipper percorre as fontes periodicamente e envia o que há de novo. Um lote só é confirmado
// (Commit) depois que a API o aceita; falhas transitórias reenviam o MESMO lote (mesmo batch_id).
type Shipper struct {
	Sources  []*Source
	Client   Sender
	Log      *slog.Logger
	Interval time.Duration
}

const (
	logsPath       = "/api/v1/agent/logs"
	maxBatchesTick = 10 // por fonte e rodada
)

func (s *Shipper) Run(ctx context.Context) {
	iv := s.Interval
	if iv <= 0 {
		iv = 3 * time.Second
	}
	defer func() {
		for _, src := range s.Sources {
			src.Close()
		}
	}()
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick executa uma rodada em todas as fontes.
func (s *Shipper) Tick(ctx context.Context) {
	for _, src := range s.Sources {
		for i := 0; i < maxBatchesTick && ctx.Err() == nil; i++ {
			if !s.ship(ctx, src) {
				break
			}
		}
	}
}

// ship envia um lote da fonte. Devolve true se há chance de haver mais para enviar.
func (s *Shipper) ship(ctx context.Context, src *Source) bool {
	entries, id, err := src.Next()
	if err != nil {
		s.Log.Warn("leitura de log falhou", "source", src.Name, "err", err)
		return false
	}
	if len(entries) == 0 {
		return false
	}
	err = s.Client.Do(ctx, http.MethodPost, logsPath, logs.Batch{BatchID: id, Entries: entries}, nil)
	var perm *agentclient.PermanentError
	switch {
	case err == nil:
	case errors.As(err, &perm) && !perm.IsAuth():
		// 4xx não-auth (validação, tamanho): reenviar nunca vai funcionar; descarta para não travar a fila.
		s.Log.Error("API rejeitou o lote de logs; descartado", "source", src.Name, "status", perm.Status,
			"code", perm.Code, "entries", len(entries))
	default:
		// auth, rede ou erro 5xx/429 (ex.: logs desativados na API, ClickHouse fora): mantém o lote e tenta de novo na próxima rodada.
		s.Log.Warn("envio de logs falhou; será repetido", "source", src.Name, "err", err)
		return false
	}
	if err := src.Commit(); err != nil {
		s.Log.Error("não foi possível gravar a posição do log", "source", src.Name, "err", err)
		return false
	}
	return len(entries) >= maxBatch
}
