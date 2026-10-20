// Package middleware contém os middlewares HTTP da API.
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/http/response"
	"sentinela/internal/netutil"
	"sentinela/internal/ratelimit"
	"sentinela/internal/telemetry"
)

type ctxKey struct{}
type infoKey struct{}

// ReqInfo é preenchida por camadas internas (ex.: autenticação) e lida pelo log de acesso, que roda por fora.
type ReqInfo struct{ UserID, Actor string }

func InfoFrom(ctx context.Context) *ReqInfo {
	i, _ := ctx.Value(infoKey{}).(*ReqInfo)
	return i
}

const RequestIDHeader = "X-Request-ID"

func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// RequestID reaproveita um ID válido recebido ou gera um novo.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !validRequestID(id) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

// Flush mantém suporte a SSE.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Recover captura panics, registra o stack no log e responde 500 genérico.
func Recover(log *slog.Logger, m *telemetry.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					log.Error("panic na requisição", "panic", rec, "stack", string(debug.Stack()),
						"request_id", RequestIDFrom(r.Context()))
					if m != nil {
						m.InternalErrs.Inc()
					}
					response.Internal(w)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Observe registra log estruturado e métricas Prometheus por requisição.
func Observe(log *slog.Logger, m *telemetry.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			info := &ReqInfo{}
			r = r.WithContext(context.WithValue(r.Context(), infoKey{}, info))
			m.InFlight.Inc()
			defer m.InFlight.Dec()
			next.ServeHTTP(sw, r)

			route := "unmatched"
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				route = rc.RoutePattern()
			}
			dur := time.Since(start)
			m.Requests.WithLabelValues(r.Method, route, strconv.Itoa(sw.status)).Inc()
			m.Latency.WithLabelValues(r.Method, route).Observe(dur.Seconds())
			if sw.status >= 500 {
				m.InternalErrs.Inc()
			}
			if route == "/healthz" || route == "/metrics" {
				return
			}
			attrs := []any{"method", r.Method, "route", route, "status", sw.status,
				"duration_ms", dur.Milliseconds(), "request_id", RequestIDFrom(r.Context())}
			if info.UserID != "" || info.Actor != "" {
				attrs = append(attrs, "user_id", info.UserID, "actor", info.Actor)
			}
			log.Info("http", attrs...)
		})
	}
}

// BodyLimit limita o tamanho do corpo das requisições.
func BodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > max {
				response.Error(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Corpo da requisição excede o limite permitido.")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout aplica um deadline ao contexto da requisição.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CORS é restritivo: só origens explicitamente permitidas recebem cabeçalhos.
func CORS(allowed []string) func(http.Handler) http.Handler {
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		set[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				w.Header().Add("Vary", "Origin")
			}
			if origin == "" || !set[origin] {
				if r.Method == http.MethodOptions && origin != "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", strings.Join([]string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"}, ", "))
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Last-Event-ID, X-CSRF-Token, X-Request-ID")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders aplica cabeçalhos defensivos a todas as respostas. A API só devolve JSON/texto, então a
// CSP bloqueia qualquer recurso; hsts liga o Strict-Transport-Security (use em produção, atrás de HTTPS).
func SecurityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("Cross-Origin-Resource-Policy", "same-site")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoStore impede que navegadores e proxies guardem respostas autenticadas. Handlers podem sobrescrever.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// RateLimit limita requisições por IP (token bucket em memória, por instância).
func RateLimit(l *ratelimit.Limiter, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, retry := l.Allow(netutil.ClientIP(r, trustProxy)); !ok {
				secs := int(retry.Seconds()) + 1
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				response.Error(w, http.StatusTooManyRequests, "RATE_LIMITED", "Muitas requisições. Tente novamente em instantes.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BearerToken protege um endpoint com token estático (ex.: /metrics para o Prometheus). Token vazio = sem proteção.
func BearerToken(token string) func(http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return func(next http.Handler) http.Handler {
		if token == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
			got := sha256.Sum256([]byte(strings.TrimSpace(tok)))
			if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
