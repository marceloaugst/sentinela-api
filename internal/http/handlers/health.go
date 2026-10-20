// Package handlers contém os handlers HTTP.
package handlers

import (
	"context"
	"net/http"
	"time"

	"sentinela/internal/http/response"
)

// Pinger é implementado por dependências essenciais (ex.: pgxpool.Pool).
type Pinger interface {
	Ping(ctx context.Context) error
}

type Health struct {
	DB      Pinger
	Version string
}

// Healthz é o liveness: o processo está de pé.
func (h Health) Healthz(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, http.StatusOK, map[string]string{"status": "ok", "version": h.Version}, nil)
}

// Readyz é o readiness: dependências essenciais respondem.
func (h Health) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.DB.Ping(ctx); err != nil {
		// detalhes do erro ficam fora da resposta
		response.Error(w, http.StatusServiceUnavailable, "NOT_READY", "Dependências indisponíveis.",
			response.ErrorDetail{Field: "database", Message: "indisponível"})
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{"status": "ready", "database": "ok"}, nil)
}
