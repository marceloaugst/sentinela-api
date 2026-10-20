package agents

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"sentinela/internal/http/response"
	"sentinela/internal/netutil"
	"sentinela/internal/ratelimit"
)

type Authenticator interface {
	Authenticate(ctx context.Context, hash []byte) (Identity, error)
}

type ctxKey struct{}

// IdentityFrom devolve a identidade autenticada do agente.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// Auth autentica agentes e aplica rate limiting: por IP (antes de consultar o banco,
// para conter tentativas com tokens inválidos) e por credencial.
type Auth struct {
	Store      Authenticator
	Log        *slog.Logger
	TrustProxy bool
	ByIP       *ratelimit.Limiter
	ByCred     *ratelimit.Limiter
}

func NewAuth(store Authenticator, log *slog.Logger, trustProxy bool) *Auth {
	return &Auth{
		Store: store, Log: log, TrustProxy: trustProxy,
		ByIP:   ratelimit.New(20, 60),
		ByCred: ratelimit.New(2, 10),
	}
}

func tooMany(w http.ResponseWriter, retry float64) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retry))))
	response.Error(w, http.StatusTooManyRequests, "RATE_LIMITED", "Muitas requisições. Tente novamente em instantes.")
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="sentinela-agent"`)
	response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Credencial ausente, inválida, expirada ou revogada.")
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netutil.ClientIP(r, a.TrustProxy)
		if ok, retry := a.ByIP.Allow(ip); !ok {
			tooMany(w, retry.Seconds())
			return
		}
		tok, ok := ParseBearer(r.Header.Get("Authorization"))
		if !ok {
			unauthorized(w)
			return
		}
		id, err := a.Store.Authenticate(r.Context(), HashToken(tok))
		switch {
		case errors.Is(err, ErrInvalidCredential):
			unauthorized(w)
			return
		case err != nil:
			a.Log.Error("falha ao autenticar agente", "err", err)
			response.Internal(w)
			return
		}
		if id.ServerStatus == "disabled" {
			response.Error(w, http.StatusForbidden, "SERVER_DISABLED", "O servidor está desativado.")
			return
		}
		if ok, retry := a.ByCred.Allow(id.CredentialID); !ok {
			tooMany(w, retry.Seconds())
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}
