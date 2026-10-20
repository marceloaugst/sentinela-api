package handlers

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"sentinela/internal/auth"
	"sentinela/internal/http/response"
	"sentinela/internal/netutil"
	"sentinela/internal/users"
	"sentinela/internal/validation"
)

type Auth struct {
	Svc        *auth.Service
	Log        *slog.Logger
	TrustProxy bool
}

type loginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type sessionView struct {
	User          any    `json:"user"`
	Via           string `json:"via"`
	CSRFToken     string `json:"csrf_token,omitempty"`
	ExpiresAt     any    `json:"expires_at,omitempty"`
	IdleExpiresAt any    `json:"idle_expires_at,omitempty"`
}

func view(u users.User, s auth.Session) sessionView {
	return sessionView{User: u, Via: auth.ViaSession, CSRFToken: s.CSRF, ExpiresAt: s.ExpiresAt, IdleExpiresAt: s.IdleExpiresAt}
}

func retryAfter(w http.ResponseWriter, d float64) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d))))
}

// POST /auth/login. Mensagem única para qualquer falha de credencial (sem enumeração de contas).
func (h Auth) Login(w http.ResponseWriter, r *http.Request) {
	var in loginInput
	if !response.Decode(w, r, &in) {
		return
	}
	var p validation.Problems
	if in.Email == "" {
		p.Add("email", "é obrigatório")
	}
	if in.Password == "" {
		p.Add("password", "é obrigatória")
	}
	if len(in.Password) > 1024 || len(in.Email) > 320 {
		p.Add("password", "tamanho excedido")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	ip := netutil.ClientIP(r, h.TrustProxy)
	res, err := h.Svc.Login(r.Context(), in.Email, in.Password, ip, r.UserAgent())
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		retryAfter(w, locked.RetryAfter.Seconds())
		response.Error(w, http.StatusTooManyRequests, "LOGIN_LOCKED", "Muitas tentativas. Tente novamente mais tarde.")
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		response.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "E-mail ou senha incorretos.")
		return
	case err != nil:
		h.Log.Error("falha no login", "err", err)
		response.Internal(w)
		return
	}
	h.Svc.SetCookie(w, res.Session)
	w.Header().Set("Cache-Control", "no-store")
	response.JSON(w, http.StatusOK, view(res.User, res.Session), nil)
}

func (h Auth) clear(w http.ResponseWriter) { h.Svc.ClearCookie(w) }

// POST /auth/logout: revoga a sessão atual e limpa o cookie.
func (h Auth) Logout(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if p.Via == auth.ViaSession {
		if err := h.Svc.RevokeSession(r.Context(), p.SessionID, "logout"); err != nil {
			h.Log.Error("falha ao revogar sessão", "err", err)
			response.Internal(w)
			return
		}
	}
	h.clear(w)
	response.NoContent(w)
}

// POST /auth/logout-all: encerra todas as sessões do usuário (todos os dispositivos).
func (h Auth) LogoutAll(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if p.Via != auth.ViaSession {
		response.Error(w, http.StatusBadRequest, "NOT_A_SESSION", "Esta operação exige uma sessão de usuário.")
		return
	}
	if _, err := h.Svc.RevokeAll(r.Context(), auditCtx(r, h.TrustProxy), p.UserID, "logout_all", ""); err != nil {
		h.Log.Error("falha ao revogar sessões", "err", err)
		response.Internal(w)
		return
	}
	h.clear(w)
	response.NoContent(w)
}

// GET /auth/me: usuário autenticado e token CSRF (reemitido após reload da página).
func (h Auth) Me(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	if p.Via == auth.ViaAPIKey {
		response.JSON(w, http.StatusOK, sessionView{
			User: map[string]any{"id": nil, "name": p.Name, "email": nil, "role": p.Role}, Via: auth.ViaAPIKey}, nil)
		return
	}
	c, err := r.Cookie(h.Svc.Config().CookieName())
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.")
		return
	}
	_, sess, err := h.Svc.ValidateSession(r.Context(), c.Value)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Autenticação necessária.")
		return
	}
	u, err := h.Svc.Users.Get(r.Context(), p.UserID)
	if err != nil {
		h.Log.Error("falha ao ler usuário", "err", err)
		response.Internal(w)
		return
	}
	response.JSON(w, http.StatusOK, view(u, sess), nil)
}

type changePasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// POST /auth/change-password: troca a senha, revoga todas as outras sessões e rotaciona a atual.
func (h Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	if p.Via != auth.ViaSession {
		response.Error(w, http.StatusBadRequest, "NOT_A_SESSION", "Esta operação exige uma sessão de usuário.")
		return
	}
	var in changePasswordInput
	if !response.Decode(w, r, &in) {
		return
	}
	var pr validation.Problems
	if in.CurrentPassword == "" {
		pr.Add("current_password", "é obrigatória")
	}
	if in.NewPassword == "" {
		pr.Add("new_password", "é obrigatória")
	}
	if len(in.CurrentPassword) > 1024 || len(in.NewPassword) > 1024 {
		pr.Add("new_password", "tamanho excedido")
	}
	if len(pr) > 0 {
		response.Validation(w, pr)
		return
	}
	ip := netutil.ClientIP(r, h.TrustProxy)
	sess, err := h.Svc.ChangePassword(r.Context(), p, in.CurrentPassword, in.NewPassword, ip, r.UserAgent())
	var locked *auth.LockedError
	var policy *auth.PolicyError
	switch {
	case errors.As(err, &locked):
		retryAfter(w, locked.RetryAfter.Seconds())
		response.Error(w, http.StatusTooManyRequests, "LOGIN_LOCKED", "Muitas tentativas. Tente novamente mais tarde.")
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		var v validation.Problems
		v.Add("current_password", "senha atual incorreta")
		response.Validation(w, v)
		return
	case errors.As(err, &policy):
		var v validation.Problems
		for _, m := range policy.Messages {
			v.Add("new_password", m)
		}
		response.Validation(w, v)
		return
	case errors.Is(err, auth.ErrSameAsCurrent):
		var v validation.Problems
		v.Add("new_password", err.Error())
		response.Validation(w, v)
		return
	case err != nil:
		h.Log.Error("falha ao trocar a senha", "err", err)
		response.Internal(w)
		return
	}
	h.Svc.SetCookie(w, sess)
	w.Header().Set("Cache-Control", "no-store")
	response.JSON(w, http.StatusOK, map[string]any{"csrf_token": sess.CSRF, "expires_at": sess.ExpiresAt, "idle_expires_at": sess.IdleExpiresAt}, nil)
}
