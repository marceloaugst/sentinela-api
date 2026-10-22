package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/passwords"
	"sentinela/internal/users"
	"sentinela/internal/validation"
)

var (
	ErrInvalidCredentials = errors.New("credenciais inválidas")
	ErrSessionInvalid     = errors.New("sessão inválida ou expirada")
	ErrSameAsCurrent      = errors.New("a nova senha deve ser diferente da atual")
)

// LockedError: tentativas demais; Retry-After indica quando tentar de novo.
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string { return "muitas tentativas de login" }

// PolicyError: a senha não atende à política.
type PolicyError struct{ Messages []string }

func (e *PolicyError) Error() string { return "senha não atende à política" }

type Config struct {
	AbsoluteTTL time.Duration // vida máxima da sessão, mesmo com uso contínuo
	IdleTTL     time.Duration // expira após esse tempo sem uso
	// Bloqueio de login (janela e duração do bloqueio são iguais, então ele se desfaz sozinho):
	LockWindow       time.Duration
	MaxFailuresPair  int // mesmo e-mail a partir do mesmo IP
	MaxFailuresIP    int // qualquer e-mail a partir do mesmo IP (credential stuffing)
	MaxFailuresEmail int // mesmo e-mail de qualquer IP (ataque distribuído)

	CookieSecure   bool
	SameSite       http.SameSite
	APIKey         string // credencial de automação opcional (papel admin, sem cookie/CSRF)
	AllowedOrigins []string
}

func (c Config) withDefaults() Config {
	if c.AbsoluteTTL <= 0 {
		c.AbsoluteTTL = 24 * time.Hour
	}
	if c.IdleTTL <= 0 {
		c.IdleTTL = 2 * time.Hour
	}
	if c.LockWindow <= 0 {
		c.LockWindow = 15 * time.Minute
	}
	if c.MaxFailuresPair <= 0 {
		c.MaxFailuresPair = 5
	}
	if c.MaxFailuresIP <= 0 {
		c.MaxFailuresIP = 20
	}
	if c.MaxFailuresEmail <= 0 {
		c.MaxFailuresEmail = 30
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteLaxMode
	}
	return c
}

// CookieName usa o prefixo __Host- quando o cookie é Secure: o navegador então só o aceita se for
// Secure, sem Domain e com Path=/, o que impede que um subdomínio o sobrescreva.
func (c Config) CookieName() string {
	if c.CookieSecure {
		return "__Host-sentinela_session"
	}
	return "sentinela_session"
}

type Service struct {
	cfg    Config
	pool   *pgxpool.Pool
	Users  *users.Repository
	Hasher *passwords.Hasher
	Log    *slog.Logger
	Now    func() time.Time
}

func NewService(cfg Config, pool *pgxpool.Pool, u *users.Repository, h *passwords.Hasher, log *slog.Logger) *Service {
	return &Service{cfg: cfg.withDefaults(), pool: pool, Users: u, Hasher: h, Log: log}
}

func (s *Service) Config() Config { return s.cfg }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func cleanIP(ip string) string {
	if p := net.ParseIP(ip); p != nil {
		return p.String()
	}
	return "0.0.0.0"
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- bloqueio por tentativas ----

// lockRetry devolve por quanto tempo o login está bloqueado para esta combinação (0 = liberado).
// Três escopos: (e-mail, IP) protege o usuário legítimo de um atacante em outro IP; IP contém
// credential stuffing; e-mail global contém ataques distribuídos. Falhas anteriores a um login bem-sucedido
// do mesmo par não contam.
func (s *Service) lockRetry(ctx context.Context, email, ip string, now time.Time) (time.Duration, error) {
	start := now.Add(-s.cfg.LockWindow)
	var pairN, ipN, emailN int
	var pairLast, ipLast, emailLast *time.Time
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM login_attempts WHERE email = $1 AND ip = $2::inet AND NOT succeeded
		   AND attempted_at > GREATEST($3::timestamptz, COALESCE((SELECT max(attempted_at) FROM login_attempts
		        WHERE email = $1 AND ip = $2::inet AND succeeded), '-infinity'::timestamptz))),
		(SELECT max(attempted_at) FROM login_attempts WHERE email = $1 AND ip = $2::inet AND NOT succeeded AND attempted_at > $3),
		(SELECT count(*) FROM login_attempts WHERE ip = $2::inet AND NOT succeeded AND attempted_at > $3),
		(SELECT max(attempted_at) FROM login_attempts WHERE ip = $2::inet AND NOT succeeded AND attempted_at > $3),
		(SELECT count(*) FROM login_attempts WHERE email = $1 AND NOT succeeded AND attempted_at > $3),
		(SELECT max(attempted_at) FROM login_attempts WHERE email = $1 AND NOT succeeded AND attempted_at > $3)`,
		email, ip, start).Scan(&pairN, &pairLast, &ipN, &ipLast, &emailN, &emailLast)
	if err != nil {
		return 0, err
	}
	var until time.Time
	consider := func(n, max int, last *time.Time) {
		if n >= max && last != nil {
			if u := last.Add(s.cfg.LockWindow); u.After(until) {
				until = u
			}
		}
	}
	consider(pairN, s.cfg.MaxFailuresPair, pairLast)
	consider(ipN, s.cfg.MaxFailuresIP, ipLast)
	consider(emailN, s.cfg.MaxFailuresEmail, emailLast)
	if until.After(now) {
		return until.Sub(now), nil
	}
	return 0, nil
}

func (s *Service) recordAttempt(ctx context.Context, email, ip string, ok bool, now time.Time) {
	if _, err := s.pool.Exec(ctx, `INSERT INTO login_attempts (email, ip, succeeded, attempted_at) VALUES ($1, $2::inet, $3, $4)`,
		trunc(email, 254), ip, ok, now); err != nil {
		s.Log.Error("falha ao registrar tentativa de login", "err", err)
	}
}

// ---- login ----

type Session struct {
	ID            string
	Token         string
	CSRF          string
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}

type LoginResult struct {
	User    users.User
	Session Session
}

func (s *Service) createSession(ctx context.Context, userID, ip, ua string, now time.Time) (Session, error) {
	token, err := newToken()
	if err != nil {
		return Session{}, err
	}
	csrf := CSRFToken(token)
	sess := Session{Token: token, CSRF: csrf, ExpiresAt: now.Add(s.cfg.AbsoluteTTL), IdleExpiresAt: now.Add(s.cfg.IdleTTL)}
	csrfHash := sha256.Sum256([]byte(csrf))
	err = s.pool.QueryRow(ctx, `INSERT INTO sessions (user_id, token_hash, csrf_hash, created_at, expires_at, last_seen_at, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$4,$6::inet,$7) RETURNING id`,
		userID, hashToken(token), csrfHash[:], now, sess.ExpiresAt, ip, trunc(ua, 255)).Scan(&sess.ID)
	return sess, err
}

// Login valida as credenciais. Todas as falhas (e-mail inexistente, senha errada, usuário desativado)
// devolvem o mesmo erro e gastam o mesmo tempo de CPU, para não revelar quais contas existem.
func (s *Service) Login(ctx context.Context, email, password, ip, userAgent string) (LoginResult, error) {
	now := s.now()
	ip = cleanIP(ip)
	norm, valid := users.NormalizeEmail(email)
	if !valid {
		norm = strings.ToLower(strings.TrimSpace(email))
	}

	if retry, err := s.lockRetry(ctx, norm, ip, now); err != nil {
		return LoginResult{}, err
	} else if retry > 0 {
		_ = audit.Write(ctx, s.pool, audit.Context{Actor: "sistema", IP: ip}, "auth.login_locked", "user", "",
			map[string]any{"email": trunc(norm, 254), "retry_after_seconds": int(retry.Seconds())})
		return LoginResult{}, &LockedError{RetryAfter: retry}
	}

	var cred users.Credentials
	var found bool
	if valid {
		c, err := s.Users.GetCredentialsByEmail(ctx, norm)
		switch {
		case err == nil:
			cred, found = c, true
		case !errors.Is(err, users.ErrNotFound):
			return LoginResult{}, err
		}
	}
	if !found {
		s.Hasher.DummyVerify(ctx, password) // mesmo custo de uma verificação real
		s.recordAttempt(ctx, norm, ip, false, now)
		return LoginResult{}, ErrInvalidCredentials
	}
	ok, needsRehash, err := s.Hasher.Verify(ctx, password, cred.PasswordHash)
	if err != nil {
		s.Log.Error("hash de senha inválido no banco", "user_id", cred.ID, "err", err)
		s.recordAttempt(ctx, norm, ip, false, now)
		return LoginResult{}, ErrInvalidCredentials
	}
	if !ok || !cred.IsActive { // usuário desativado nunca entra, mesmo com a senha certa
		s.recordAttempt(ctx, norm, ip, false, now)
		return LoginResult{}, ErrInvalidCredentials
	}

	newHash := ""
	if needsRehash {
		if h, err := s.Hasher.Hash(ctx, password); err == nil {
			newHash = h
		}
	}
	s.recordAttempt(ctx, norm, ip, true, now)
	if err := s.Users.MarkLogin(ctx, cred.ID, now, newHash); err != nil {
		return LoginResult{}, err
	}
	sess, err := s.createSession(ctx, cred.ID, ip, userAgent, now) // token novo a cada login (sem fixação de sessão)
	if err != nil {
		return LoginResult{}, err
	}
	_ = audit.Write(ctx, s.pool, audit.Context{Actor: cred.Email, UserID: cred.ID, IP: ip}, "auth.login", "user", cred.ID,
		map[string]any{"session_id": sess.ID})
	return LoginResult{User: cred.User, Session: sess}, nil
}

// ---- sessões ----

// ValidateSession valida o token de sessão. A função de papel/estado do usuário é lida do banco a cada
// requisição: desativar o usuário ou mudar o papel vale imediatamente.
func (s *Service) ValidateSession(ctx context.Context, token string) (Principal, Session, error) {
	if !validTokenFormat(token) {
		return Principal{}, Session{}, ErrSessionInvalid
	}
	now := s.now()
	var p Principal
	var sess Session
	var lastSeen time.Time
	var active bool
	var role string
	err := s.pool.QueryRow(ctx, `SELECT s.id, s.user_id, s.expires_at, s.last_seen_at, u.name, u.email, u.role, u.is_active
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL`, hashToken(token)).
		Scan(&sess.ID, &p.UserID, &sess.ExpiresAt, &lastSeen, &p.Name, &p.Email, &role, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, Session{}, ErrSessionInvalid
	}
	if err != nil {
		return Principal{}, Session{}, err
	}
	if !active || !now.Before(sess.ExpiresAt) || !now.Before(lastSeen.Add(s.cfg.IdleTTL)) {
		return Principal{}, Session{}, ErrSessionInvalid
	}
	// renovação deslizante do prazo de inatividade (no máximo 1 gravação por minuto por sessão)
	if now.Sub(lastSeen) >= time.Minute {
		if _, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, sess.ID, now); err == nil {
			lastSeen = now
		}
	}
	p.Role, p.SessionID, p.Via = Role(role), sess.ID, ViaSession
	sess.Token, sess.CSRF, sess.IdleExpiresAt = token, CSRFToken(token), lastSeen.Add(s.cfg.IdleTTL)
	return p, sess, nil
}

// SessionValid reavalia uma sessão já autenticada (usado para encerrar streams SSE de sessões revogadas,
// usuários desativados ou sessões vencidas). Chave de API é sempre válida.
func (s *Service) SessionValid(ctx context.Context, p Principal) bool {
	if p.Via != ViaSession {
		return true
	}
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND u.is_active)`, p.SessionID, s.now()).Scan(&ok)
	return err == nil && ok
}

func (s *Service) RevokeSession(ctx context.Context, sessionID, reason string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at = $3, revoked_reason = $2 WHERE id = $1 AND revoked_at IS NULL`, sessionID, reason, s.now())
	return err
}

func (s *Service) RevokeAll(ctx context.Context, ac audit.Context, userID, reason, except string) (int64, error) {
	return s.Users.RevokeSessions(ctx, ac, userID, reason, except)
}

// ---- senha ----

// ChangePassword exige a senha atual (cada erro conta para o bloqueio, pois uma sessão sequestrada
// poderia tentar adivinhá-la), aplica a política, revoga TODAS as sessões e devolve uma sessão nova
// para este dispositivo (rotação do token).
func (s *Service) ChangePassword(ctx context.Context, p Principal, current, newPassword, ip, ua string) (Session, error) {
	now := s.now()
	ip = cleanIP(ip)
	if p.Via != ViaSession {
		return Session{}, ErrInvalidCredentials
	}
	if retry, err := s.lockRetry(ctx, p.Email, ip, now); err != nil {
		return Session{}, err
	} else if retry > 0 {
		return Session{}, &LockedError{RetryAfter: retry}
	}
	cred, err := s.Users.GetCredentials(ctx, p.UserID)
	if err != nil {
		return Session{}, err
	}
	ok, _, err := s.Hasher.Verify(ctx, current, cred.PasswordHash)
	if err != nil || !ok {
		s.recordAttempt(ctx, p.Email, ip, false, now)
		return Session{}, ErrInvalidCredentials
	}
	if msgs := passwords.Validate(newPassword, cred.Email, cred.Name); len(msgs) > 0 {
		return Session{}, &PolicyError{Messages: msgs}
	}
	if newPassword == current {
		return Session{}, ErrSameAsCurrent
	}
	hash, err := s.Hasher.Hash(ctx, newPassword)
	if err != nil {
		return Session{}, err
	}
	ac := audit.Context{Actor: p.Actor(), UserID: p.UserID, IP: ip}
	if _, _, err := s.Users.Update(ctx, ac, p.UserID, users.UpdateParams{PasswordHash: &hash}); err != nil {
		return Session{}, err
	}
	return s.createSession(ctx, p.UserID, ip, ua, now)
}

// ---- administração de contas ----

// CreateUser aplica a política (já validada pelo chamador) e grava o hash.
func (s *Service) CreateUser(ctx context.Context, ac audit.Context, in users.CreateInput) (users.User, error) {
	hash, err := s.Hasher.Hash(ctx, in.Password)
	if err != nil {
		return users.User{}, err
	}
	return s.Users.Create(ctx, ac, users.NewUser{Name: in.Name, Email: in.Email, Role: in.Role, PasswordHash: hash})
}

func (s *Service) UpdateUser(ctx context.Context, ac audit.Context, id string, in users.UpdateInput) (users.User, int64, error) {
	p := users.UpdateParams{Name: in.Name, Email: in.Email, Role: in.Role, IsActive: in.IsActive}
	if in.Password != nil {
		h, err := s.Hasher.Hash(ctx, *in.Password)
		if err != nil {
			return users.User{}, 0, err
		}
		p.PasswordHash = &h
	}
	return s.Users.Update(ctx, ac, id, p)
}

// Bootstrap cria o primeiro administrador SOMENTE se não existir nenhum usuário. Idempotente e seguro
// para rodar a cada inicialização.
func (s *Service) Bootstrap(ctx context.Context, email, name, password string) (bool, error) {
	n, err := s.Users.Count(ctx)
	if err != nil || n > 0 {
		return false, err
	}
	in := users.CreateInput{Name: name, Email: email, Role: users.RoleAdmin, Password: password}
	if p := in.Validate(); len(p) > 0 {
		return false, &BootstrapError{Problems: p}
	}
	if _, err := s.CreateUser(ctx, audit.Context{Actor: "bootstrap"}, in); err != nil {
		if errors.Is(err, users.ErrConflict) {
			return false, nil // corrida entre instâncias: outra criou primeiro
		}
		return false, err
	}
	return true, nil
}

type BootstrapError struct{ Problems validation.Problems }

func (e *BootstrapError) Error() string { return "dados do administrador inicial inválidos" }

// ClearLoginAttempts apaga as tentativas de login do e-mail, desfazendo um bloqueio por tentativas
// (usado pelo comando seed-user). Devolve quantas linhas foram removidas.
func (s *Service) ClearLoginAttempts(ctx context.Context, email string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM login_attempts WHERE email = $1`, email)
	return tag.RowsAffected(), err
}

// Cleanup remove sessões vencidas/revogadas há tempo e tentativas de login antigas. Devolve (sessões, tentativas).
func (s *Service) Cleanup(ctx context.Context) (int64, int64, error) {
	now := s.now()
	t1, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $2)`,
		now.Add(-24*time.Hour), now.Add(-7*24*time.Hour))
	if err != nil {
		return 0, 0, err
	}
	t2, err := s.pool.Exec(ctx, `DELETE FROM login_attempts WHERE attempted_at < $1`, now.Add(-30*24*time.Hour))
	if err != nil {
		return t1.RowsAffected(), 0, err
	}
	return t1.RowsAffected(), t2.RowsAffected(), nil
}
