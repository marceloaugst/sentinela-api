package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sentinela/internal/http/middleware"
	"sentinela/internal/http/response"
)

func unauthorized(w http.ResponseWriter) {
	response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.")
}

func isSafe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (s *Service) apiKeyMatches(presented string) bool {
	if s.cfg.APIKey == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(presented)), sha256.Sum256([]byte(s.cfg.APIKey))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// SetCookie grava o cookie de sessão: HttpOnly (inacessível a scripts), Secure, SameSite e prazo absoluto.
func (s *Service) SetCookie(w http.ResponseWriter, sess Session) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.CookieName(), Value: sess.Token, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure,
		SameSite: s.cfg.SameSite, Expires: sess.ExpiresAt, MaxAge: int(time.Until(sess.ExpiresAt).Seconds()),
	})
}

func (s *Service) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.CookieName(), Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure,
		SameSite: s.cfg.SameSite, MaxAge: -1, Expires: time.Unix(0, 0),
	})
}

// originAllowed: a origem deve ser a própria API (mesmo host) ou uma das origens configuradas (CORS).
func (s *Service) originAllowed(r *http.Request, origin string) bool {
	for _, o := range s.cfg.AllowedOrigins {
		if o == origin {
			return true
		}
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

// Authenticate resolve quem está chamando e aplica a proteção CSRF.
//
//  1. Authorization: Bearer <ADMIN_API_KEY> (se configurada) → papel admin, sem CSRF (não é credencial
//     ambiente: o navegador não a envia sozinho).
//  2. Cookie de sessão → usuário e papel lidos do banco; métodos que alteram estado exigem
//     X-CSRF-Token válido e, se houver cabeçalho Origin, uma origem permitida.
//
// Qualquer outra coisa → 401. Um cabeçalho Authorization presente porém inválido NÃO cai para o cookie.
func (s *Service) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); h != "" {
			scheme, tok, ok := strings.Cut(h, " ")
			if !ok || !strings.EqualFold(scheme, "Bearer") || !s.apiKeyMatches(strings.TrimSpace(tok)) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				unauthorized(w)
				return
			}
			p := Principal{Name: "API key", Role: Admin, Via: ViaAPIKey}
			s.serve(next, w, r, p)
			return
		}
		c, err := r.Cookie(s.cfg.CookieName())
		if err != nil || c.Value == "" {
			unauthorized(w)
			return
		}
		p, sess, err := s.ValidateSession(r.Context(), c.Value)
		if err != nil {
			if err == ErrSessionInvalid {
				s.ClearCookie(w) // cookie vencido/revogado: o navegador para de enviá-lo
				unauthorized(w)
				return
			}
			s.Log.Error("falha ao autenticar sessão", "err", err)
			response.Internal(w)
			return
		}
		if !isSafe(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(r, origin) {
				response.Error(w, http.StatusForbidden, "ORIGIN_NOT_ALLOWED", "Origem não permitida.")
				return
			}
			if !csrfEqual(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
				response.Error(w, http.StatusForbidden, "CSRF_INVALID", "Token CSRF ausente ou inválido.")
				return
			}
		}
		s.serve(next, w, r, p)
	})
}

func (s *Service) serve(next http.Handler, w http.ResponseWriter, r *http.Request, p Principal) {
	if info := middleware.InfoFrom(r.Context()); info != nil {
		info.UserID, info.Actor = p.UserID, p.Actor()
	}
	next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
}

// Require exige um papel mínimo (403 se insuficiente). Deve vir depois de Authenticate.
func Require(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				unauthorized(w)
				return
			}
			if !p.Role.AtLeast(min) {
				response.Error(w, http.StatusForbidden, "FORBIDDEN", "Você não tem permissão para esta operação.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
