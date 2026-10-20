//go:build integration

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/auth"
	"sentinela/internal/passwords"
	"sentinela/internal/testutil"
	"sentinela/internal/users"
)

var ctx = context.Background()
var light = passwords.Params{MemoryKiB: 256, Time: 1, Threads: 1}

const pw = "orquidea-azul-montanha-77"

type fx struct {
	t    *testing.T
	pool *pgxpool.Pool
	svc  *auth.Service
	now  time.Time
}

func newFx(t *testing.T, mut ...func(*auth.Config)) *fx {
	t.Helper()
	pool := testutil.NewDB(t)
	f := &fx{t: t, pool: pool, now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	cfg := auth.Config{AbsoluteTTL: 24 * time.Hour, IdleTTL: 2 * time.Hour, LockWindow: 15 * time.Minute,
		MaxFailuresPair: 5, MaxFailuresIP: 20, MaxFailuresEmail: 30}
	for _, m := range mut {
		m(&cfg)
	}
	f.svc = auth.NewService(cfg, pool, users.NewRepository(pool), passwords.NewHasher(light, 4), slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.svc.Now = func() time.Time { return f.now }
	return f
}

func (f *fx) user(email, role string) users.User {
	f.t.Helper()
	u, err := f.svc.CreateUser(ctx, audit.Context{Actor: "teste"}, users.CreateInput{Name: "Pessoa", Email: email, Role: role, Password: pw})
	if err != nil {
		f.t.Fatal(err)
	}
	return u
}

func (f *fx) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (f *fx) login(email, password, ip string) (auth.LoginResult, error) {
	return f.svc.Login(ctx, email, password, ip, "teste/1.0")
}

func (f *fx) advance(d time.Duration) { f.now = f.now.Add(d) }

func isLocked(err error) (*auth.LockedError, bool) {
	var l *auth.LockedError
	return l, errors.As(err, &l)
}

func TestLoginCreatesAHashedSessionAndNeverStoresSecrets(t *testing.T) {
	f := newFx(t)
	u := f.user("ana@exemplo.com", users.RoleOperator)
	res, err := f.login(" ANA@Exemplo.com ", pw, "10.0.0.1") // e-mail é normalizado
	if err != nil {
		t.Fatal(err)
	}
	tok := res.Session.Token
	if !strings.HasPrefix(tok, "ses_") || len(tok) != 68 || res.User.ID != u.ID || res.Session.CSRF == "" || res.Session.CSRF == tok {
		t.Errorf("sessão: %+v", res.Session)
	}
	if !res.Session.ExpiresAt.Equal(f.now.Add(24*time.Hour)) || !res.Session.IdleExpiresAt.Equal(f.now.Add(2*time.Hour)) {
		t.Errorf("prazos: %v %v", res.Session.ExpiresAt, res.Session.IdleExpiresAt)
	}
	// só o hash do token é guardado
	if f.count(`SELECT count(*) FROM sessions WHERE token_hash = $1`, []byte(tok)) != 0 || f.count(`SELECT count(*) FROM sessions WHERE position($1 in encode(token_hash,'hex')) > 0`, tok) != 0 {
		t.Error("token em texto puro no banco")
	}
	var hash string
	f.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, u.ID).Scan(&hash)
	if !strings.HasPrefix(hash, "$argon2id$v=19$") || strings.Contains(hash, pw) {
		t.Errorf("hash: %s", hash)
	}
	if f.count(`SELECT count(*) FROM users WHERE last_login_at = $1`, f.now) != 1 {
		t.Error("last_login_at")
	}
	if f.count(`SELECT count(*) FROM audit_logs WHERE action='auth.login' AND actor_user_id = $1`, u.ID) != 1 {
		t.Error("login deveria ser auditado com o usuário")
	}
	if f.count(`SELECT count(*) FROM audit_logs WHERE metadata::text LIKE '%' || $1 || '%' OR metadata::text LIKE '%argon2%' OR metadata::text LIKE '%ses\_%'`, pw) != 0 {
		t.Error("segredo na auditoria")
	}
	// dois logins => tokens distintos, sem reaproveitar sessão (anti-fixação)
	res2, _ := f.login("ana@exemplo.com", pw, "10.0.0.1")
	if res2.Session.Token == tok || res2.Session.ID == res.Session.ID {
		t.Error("cada login cria uma sessão nova")
	}
}

func TestEveryLoginFailureLooksTheSame(t *testing.T) {
	f := newFx(t)
	f.user("ana@exemplo.com", users.RoleViewer)
	off := f.user("off@exemplo.com", users.RoleViewer)
	inactive := false
	if _, _, err := f.svc.UpdateUser(ctx, audit.Context{Actor: "t"}, off.ID, users.UpdateInput{IsActive: &inactive}); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"senha errada":          {"ana@exemplo.com", "senha-errada-qualquer-1"},
		"e-mail inexistente":    {"ninguem@exemplo.com", pw},
		"usuário desativado":    {"off@exemplo.com", pw}, // senha CERTA, mas a conta está desativada
		"e-mail malformado":     {"nao-e-email", pw},
		"vazio":                 {"", ""},
		"injeção":               {"x' OR '1'='1@a.com", "' OR '1'='1"},
		"senha com bytes nulos": {"ana@exemplo.com", "a\x00b"},
	}
	for name, c := range cases {
		_, err := f.login(c[0], c[1], "10.0.0.9")
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
		f.advance(time.Minute) // evita disparar o bloqueio neste teste
		f.advance(15 * time.Minute)
	}
	if f.count(`SELECT count(*) FROM sessions`) != 0 {
		t.Error("nenhuma sessão deveria existir")
	}
	if f.count(`SELECT count(*) FROM login_attempts WHERE NOT succeeded`) != len(cases) {
		t.Error("toda falha deve ficar registrada")
	}
}

func TestLockoutScopesAndRecovery(t *testing.T) {
	f := newFx(t)
	f.user("vitima@exemplo.com", users.RoleViewer)
	attackerIP, userIP := "203.0.113.5", "198.51.100.7"

	// 5 falhas do atacante para a conta da vítima
	for i := 0; i < 5; i++ {
		if _, err := f.login("vitima@exemplo.com", fmt.Sprintf("chute-errado-%d-xx", i), attackerIP); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("tentativa %d: %v", i, err)
		}
	}
	// a 6ª é bloqueada ANTES de verificar a senha — mesmo com a senha certa
	_, err := f.login("vitima@exemplo.com", pw, attackerIP)
	l, ok := isLocked(err)
	if !ok || l.RetryAfter < 14*time.Minute || l.RetryAfter > 15*time.Minute {
		t.Fatalf("esperava bloqueio de ~15 min: %v", err)
	}
	if f.count(`SELECT count(*) FROM login_attempts`) != 5 {
		t.Error("tentativas durante o bloqueio não devem ser gravadas (não prolongam o bloqueio)")
	}
	if f.count(`SELECT count(*) FROM audit_logs WHERE action='auth.login_locked'`) != 1 {
		t.Error("bloqueio deve ser auditado")
	}
	// ANTI-DoS: o atacante NÃO consegue trancar o usuário legítimo, que entra de outro IP
	if _, err := f.login("vitima@exemplo.com", pw, userIP); err != nil {
		t.Fatalf("usuário legítimo bloqueado por um atacante em outro IP: %v", err)
	}
	// o bloqueio é por tempo e se desfaz sozinho
	f.advance(10 * time.Minute)
	if l2, ok := isLocked(func() error { _, e := f.login("vitima@exemplo.com", pw, attackerIP); return e }()); !ok || l2.RetryAfter >= l.RetryAfter {
		t.Error("o tempo restante deve diminuir")
	}
	f.advance(6 * time.Minute)
	if _, err := f.login("vitima@exemplo.com", pw, attackerIP); err != nil {
		t.Fatalf("após a janela deveria liberar: %v", err)
	}

	// um login bem-sucedido zera a contagem do par (falhas anteriores não se acumulam)
	f2 := newFx(t)
	f2.user("a@exemplo.com", users.RoleViewer)
	for round := 0; round < 3; round++ {
		for i := 0; i < 4; i++ {
			f2.login("a@exemplo.com", "errada-errada-12345", "192.0.2.1")
		}
		if _, err := f2.login("a@exemplo.com", pw, "192.0.2.1"); err != nil {
			t.Fatalf("rodada %d: 4 falhas + sucesso não deveria bloquear: %v", round, err)
		}
	}
}

func TestIPAndEmailWideLockouts(t *testing.T) {
	// por IP: credential stuffing (muitos e-mails, poucas tentativas por e-mail)
	f := newFx(t)
	f.user("real@exemplo.com", users.RoleViewer)
	for i := 0; i < 20; i++ {
		f.login(fmt.Sprintf("alvo%d@exemplo.com", i), "chute-chute-chute-1", "203.0.113.50")
	}
	if _, err := f.login("real@exemplo.com", pw, "203.0.113.50"); func() bool { _, ok := isLocked(err); return !ok }() {
		t.Errorf("o IP com 20 falhas deveria estar bloqueado para qualquer e-mail: %v", err)
	}
	if _, err := f.login("real@exemplo.com", pw, "203.0.113.51"); err != nil {
		t.Errorf("outro IP não é afetado: %v", err)
	}

	// por e-mail: ataque distribuído (muitos IPs, poucas tentativas por IP)
	g := newFx(t)
	g.user("alvo@exemplo.com", users.RoleViewer)
	for i := 0; i < 30; i++ {
		g.login("alvo@exemplo.com", "chute-chute-chute-1", fmt.Sprintf("198.18.%d.%d", i/200, i%200+1))
	}
	_, err := g.login("alvo@exemplo.com", pw, "192.0.2.200") // IP novo e limpo
	if _, ok := isLocked(err); !ok {
		t.Errorf("30 falhas distribuídas deveriam bloquear a conta para todos os IPs: %v", err)
	}
	// e se desfaz com o tempo
	g.advance(16 * time.Minute)
	if _, err := g.login("alvo@exemplo.com", pw, "192.0.2.200"); err != nil {
		t.Errorf("após a janela: %v", err)
	}
	// contas inexistentes também são contadas (nenhuma diferença observável de uma conta real)
	h := newFx(t)
	for i := 0; i < 5; i++ {
		h.login("fantasma@exemplo.com", "chute-chute-chute-1", "203.0.113.9")
	}
	if _, err := h.login("fantasma@exemplo.com", pw, "203.0.113.9"); func() bool { _, ok := isLocked(err); return !ok }() {
		t.Errorf("e-mail inexistente deve bloquear igual a um existente: %v", err)
	}
}

func TestSessionExpiryIdleSlidingAbsoluteRevocationAndDeactivation(t *testing.T) {
	f := newFx(t)
	u := f.user("ana@exemplo.com", users.RoleOperator)
	res, _ := f.login("ana@exemplo.com", pw, "10.0.0.1")
	tok := res.Session.Token

	p, s, err := f.svc.ValidateSession(ctx, tok)
	if err != nil || p.UserID != u.ID || p.Role != auth.Operator || p.Via != auth.ViaSession || s.CSRF != auth.CSRFToken(tok) {
		t.Fatalf("válida: %+v %v", p, err)
	}
	// renovação deslizante: usar a sessão antes de 2 h empurra o prazo de inatividade
	f.advance(90 * time.Minute)
	if _, s2, err := f.svc.ValidateSession(ctx, tok); err != nil || !s2.IdleExpiresAt.Equal(f.now.Add(2*time.Hour)) {
		t.Fatalf("renovação: %v %v", err, s2.IdleExpiresAt)
	}
	f.advance(90 * time.Minute) // 3 h no total, mas só 1h30 desde o último uso
	if _, _, err := f.svc.ValidateSession(ctx, tok); err != nil {
		t.Fatalf("não deveria expirar por inatividade: %v", err)
	}
	// inatividade real
	f.advance(2*time.Hour + time.Second)
	if _, _, err := f.svc.ValidateSession(ctx, tok); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Errorf("deveria expirar por inatividade: %v", err)
	}

	// vida máxima: mesmo usando sempre, a sessão morre em 24 h
	res, _ = f.login("ana@exemplo.com", pw, "10.0.0.1")
	start := f.now
	for f.now.Sub(start) < 23*time.Hour {
		f.advance(time.Hour)
		if _, _, err := f.svc.ValidateSession(ctx, res.Session.Token); err != nil {
			t.Fatalf("a %v: %v", f.now.Sub(start), err)
		}
	}
	f.advance(61 * time.Minute)
	if _, _, err := f.svc.ValidateSession(ctx, res.Session.Token); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Errorf("deveria expirar pelo prazo absoluto: %v", err)
	}

	// revogação
	res, _ = f.login("ana@exemplo.com", pw, "10.0.0.1")
	if err := f.svc.RevokeSession(ctx, res.Session.ID, "logout"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ValidateSession(ctx, res.Session.Token); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Errorf("revogada: %v", err)
	}

	// o papel é lido do banco a cada requisição: vale imediatamente; desativar derruba a sessão na hora
	res, _ = f.login("ana@exemplo.com", pw, "10.0.0.1")
	viewer := users.RoleViewer
	if _, _, err := f.svc.UpdateUser(ctx, audit.Context{Actor: "t"}, u.ID, users.UpdateInput{Role: &viewer}); err == nil {
		// é o único administrador? não: ana é operadora, então a mudança é permitida
	} else {
		t.Fatal(err)
	}
	if p, _, _ := f.svc.ValidateSession(ctx, res.Session.Token); p.Role != auth.Viewer {
		t.Errorf("novo papel deveria valer na hora: %v", p.Role)
	}
	off := false
	// revoga todas as sessões ainda não revogadas, inclusive as já vencidas (3 dos 4 logins; 1 foi encerrada por logout)
	if _, revoked, err := f.svc.UpdateUser(ctx, audit.Context{Actor: "t"}, u.ID, users.UpdateInput{IsActive: &off}); err != nil || revoked != 3 {
		t.Fatalf("desativar: revogadas=%d err=%v", revoked, err)
	}
	if _, _, err := f.svc.ValidateSession(ctx, res.Session.Token); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Errorf("sessão de usuário desativado: %v", err)
	}
	if f.svc.SessionValid(ctx, auth.Principal{Via: auth.ViaSession, SessionID: res.Session.ID}) {
		t.Error("SessionValid deveria ser falso")
	}
	if !f.svc.SessionValid(ctx, auth.Principal{Via: auth.ViaAPIKey}) {
		t.Error("chave de API é sempre válida")
	}
	// formatos inválidos nem chegam ao banco
	for _, bad := range []string{"", "x", "ses_" + strings.Repeat("0", 64), strings.Repeat("a", 68)} {
		if _, _, err := f.svc.ValidateSession(ctx, bad); !errors.Is(err, auth.ErrSessionInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestChangePassword(t *testing.T) {
	f := newFx(t)
	u := f.user("ana@exemplo.com", users.RoleViewer)
	dev1, _ := f.login("ana@exemplo.com", pw, "10.0.0.1")
	dev2, _ := f.login("ana@exemplo.com", pw, "10.0.0.2")
	p, _, _ := f.svc.ValidateSession(ctx, dev1.Session.Token)

	if _, err := f.svc.ChangePassword(ctx, p, "senha-atual-errada-1", "nova-senha-bem-longa-9", "10.0.0.1", "ua"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("senha atual errada: %v", err)
	}
	var pe *auth.PolicyError
	if _, err := f.svc.ChangePassword(ctx, p, pw, "curta", "10.0.0.1", "ua"); !errors.As(err, &pe) || len(pe.Messages) == 0 {
		t.Errorf("política: %v", err)
	}
	if _, err := f.svc.ChangePassword(ctx, p, pw, pw, "10.0.0.1", "ua"); !errors.Is(err, auth.ErrSameAsCurrent) {
		t.Errorf("mesma senha: %v", err)
	}
	if _, err := f.svc.ChangePassword(ctx, auth.Principal{Via: auth.ViaAPIKey}, pw, "nova-senha-bem-longa-9", "10.0.0.1", "ua"); err == nil {
		t.Error("chave de API não troca senha")
	}

	sess, err := f.svc.ChangePassword(ctx, p, pw, "nova-senha-bem-longa-9", "10.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"este dispositivo (token antigo)": dev1.Session.Token, "outro dispositivo": dev2.Session.Token} {
		if _, _, err := f.svc.ValidateSession(ctx, tok); !errors.Is(err, auth.ErrSessionInvalid) {
			t.Errorf("%s deveria ser revogado: %v", name, err)
		}
	}
	if _, _, err := f.svc.ValidateSession(ctx, sess.Token); err != nil || sess.Token == dev1.Session.Token {
		t.Errorf("token novo (rotação): %v", err)
	}
	if _, err := f.login("ana@exemplo.com", pw, "10.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Error("a senha antiga não pode mais funcionar")
	}
	if _, err := f.login("ana@exemplo.com", "nova-senha-bem-longa-9", "10.0.0.1"); err != nil {
		t.Errorf("senha nova: %v", err)
	}
	if f.count(`SELECT count(*) FROM users WHERE id=$1 AND password_changed_at > created_at`, u.ID) != 1 {
		t.Error("password_changed_at")
	}

	// adivinhar a senha atual com uma sessão sequestrada também é contido
	g := newFx(t)
	g.user("b@exemplo.com", users.RoleViewer)
	r, _ := g.login("b@exemplo.com", pw, "10.0.0.1")
	bp, _, _ := g.svc.ValidateSession(ctx, r.Session.Token)
	g.advance(time.Second) // falhas só contam se forem POSTERIORES ao último login bem-sucedido do par
	for i := 0; i < 5; i++ {
		g.svc.ChangePassword(ctx, bp, fmt.Sprintf("chute-errado-%d-xx", i), "nova-senha-bem-longa-9", "10.0.0.1", "ua")
	}
	if _, err := g.svc.ChangePassword(ctx, bp, pw, "nova-senha-bem-longa-9", "10.0.0.1", "ua"); func() bool { _, ok := isLocked(err); return !ok }() {
		t.Errorf("deveria bloquear após 5 tentativas: %v", err)
	}
}

func TestStrongerParametersRehashOnLogin(t *testing.T) {
	f := newFx(t)
	weak := passwords.NewHasher(passwords.Params{MemoryKiB: 64, Time: 1, Threads: 1}, 1)
	h, _ := weak.Hash(ctx, pw)
	var id string
	f.pool.QueryRow(ctx, `INSERT INTO users (name, email, password_hash, role) VALUES ('Ana','ana@exemplo.com',$1,'viewer') RETURNING id`, h).Scan(&id)
	if _, err := f.login("ana@exemplo.com", pw, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	var now string
	f.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, id).Scan(&now)
	if now == h || !strings.Contains(now, "m=256,t=1,p=1") {
		t.Errorf("deveria ter sido reprocessado com os parâmetros atuais: %s", now)
	}
	if _, err := f.login("ana@exemplo.com", pw, "10.0.0.1"); err != nil {
		t.Errorf("login após rehash: %v", err)
	}
}

func TestBootstrapCreatesTheFirstAdminOnlyOnce(t *testing.T) {
	f := newFx(t)
	var be *auth.BootstrapError
	if _, err := f.svc.Bootstrap(ctx, "admin@exemplo.com", "Admin", "curta"); !errors.As(err, &be) {
		t.Fatalf("senha fraca: %v", err)
	}
	if f.count(`SELECT count(*) FROM users`) != 0 {
		t.Fatal("nada deveria ter sido criado")
	}
	created, err := f.svc.Bootstrap(ctx, "admin@exemplo.com", "Administrador", pw)
	if err != nil || !created {
		t.Fatalf("%v %v", created, err)
	}
	if again, err := f.svc.Bootstrap(ctx, "outro@exemplo.com", "Outro", pw); err != nil || again {
		t.Errorf("com usuários existentes não cria nada: %v %v", again, err)
	}
	if f.count(`SELECT count(*) FROM users WHERE role='admin' AND email='admin@exemplo.com'`) != 1 || f.count(`SELECT count(*) FROM users`) != 1 {
		t.Error("exatamente um admin")
	}
	if _, err := f.login("admin@exemplo.com", pw, "10.0.0.1"); err != nil {
		t.Errorf("o admin criado deve conseguir entrar: %v", err)
	}
	// corrida entre instâncias: só uma cria
	g := newFx(t)
	var wg sync.WaitGroup
	var made sync.Map
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if c, err := g.svc.Bootstrap(ctx, "admin@exemplo.com", "Admin", pw); err == nil && c {
				made.Store(i, true)
			}
		}(i)
	}
	wg.Wait()
	n := 0
	made.Range(func(_, _ any) bool { n++; return true })
	if n != 1 || g.count(`SELECT count(*) FROM users`) != 1 {
		t.Errorf("criações: %d, usuários: %d", n, g.count(`SELECT count(*) FROM users`))
	}
}

func TestCleanupRemovesOnlyOldSessionsAndAttempts(t *testing.T) {
	f := newFx(t)
	f.user("ana@exemplo.com", users.RoleViewer)
	old, _ := f.login("ana@exemplo.com", pw, "10.0.0.1")
	f.advance(3 * 24 * time.Hour) // a sessão antiga venceu há 2 dias
	fresh, _ := f.login("ana@exemplo.com", pw, "10.0.0.1")
	f.pool.Exec(ctx, `UPDATE login_attempts SET attempted_at = $1 WHERE id = (SELECT min(id) FROM login_attempts)`, f.now.Add(-40*24*time.Hour))
	s, a, err := f.svc.Cleanup(ctx)
	if err != nil || s != 1 || a != 1 {
		t.Fatalf("sessões=%d tentativas=%d err=%v", s, a, err)
	}
	if f.count(`SELECT count(*) FROM sessions WHERE id=$1`, old.Session.ID) != 0 || f.count(`SELECT count(*) FROM sessions WHERE id=$1`, fresh.Session.ID) != 1 {
		t.Error("só a sessão vencida deve sair")
	}
}

func TestLastAdminCanNeverBeRemoved(t *testing.T) {
	f := newFx(t)
	a1 := f.user("a1@exemplo.com", users.RoleAdmin)
	a2 := f.user("a2@exemplo.com", users.RoleAdmin)
	f.user("op@exemplo.com", users.RoleOperator)
	off, viewer := false, users.RoleViewer
	ac := audit.Context{Actor: "t"}

	// com dois admins é possível desativar um, mas não o último
	if _, _, err := f.svc.UpdateUser(ctx, ac, a2.ID, users.UpdateInput{IsActive: &off}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.UpdateUser(ctx, ac, a1.ID, users.UpdateInput{IsActive: &off}); !errors.Is(err, users.ErrLastAdmin) {
		t.Errorf("desativar o último: %v", err)
	}
	if _, _, err := f.svc.UpdateUser(ctx, ac, a1.ID, users.UpdateInput{Role: &viewer}); !errors.Is(err, users.ErrLastAdmin) {
		t.Errorf("rebaixar o último: %v", err)
	}
	// alterar outros campos do último admin é livre
	name := "Novo Nome"
	if u, _, err := f.svc.UpdateUser(ctx, ac, a1.ID, users.UpdateInput{Name: &name}); err != nil || u.Name != name {
		t.Errorf("renomear: %v", err)
	}
	on := true
	f.svc.UpdateUser(ctx, ac, a2.ID, users.UpdateInput{IsActive: &on})

	// concorrência: dois admins se rebaixam AO MESMO TEMPO; exatamente um deve conseguir
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{a1.ID, a2.ID} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, _, err := f.svc.UpdateUser(ctx, ac, id, users.UpdateInput{Role: &viewer})
			results <- err
		}(id)
	}
	wg.Wait()
	close(results)
	ok, last := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, users.ErrLastAdmin):
			last++
		default:
			t.Error(err)
		}
	}
	if ok != 1 || last != 1 || f.count(`SELECT count(*) FROM users WHERE role='admin' AND is_active`) != 1 {
		t.Errorf("rebaixamentos concorrentes: sucesso=%d bloqueado=%d admins=%d", ok, last, f.count(`SELECT count(*) FROM users WHERE role='admin' AND is_active`))
	}
	if _, err := f.svc.Users.Get(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("inexistente: %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, ac, users.CreateInput{Name: "x", Email: "A1@exemplo.com", Role: users.RoleViewer, Password: pw}); !errors.Is(err, users.ErrConflict) {
		t.Errorf("e-mail duplicado (sem diferenciar maiúsculas): %v", err)
	}
}

// Se o login pulasse o hash quando o e-mail não existe, o tempo de resposta revelaria quais contas existem.
func TestLoginTimingDoesNotRevealWhichAccountsExist(t *testing.T) {
	pool := testutil.NewDB(t)
	heavy := passwords.Params{MemoryKiB: 16 * 1024, Time: 2, Threads: 1} // custo de hash domina o tempo
	svc := auth.NewService(auth.Config{}, pool, users.NewRepository(pool), passwords.NewHasher(heavy, 4), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := svc.CreateUser(ctx, audit.Context{Actor: "t"}, users.CreateInput{Name: "Pessoa", Email: "real@exemplo.com", Role: users.RoleViewer, Password: pw}); err != nil {
		t.Fatal(err)
	}
	best := func(email string) time.Duration {
		min := time.Hour
		for i := 0; i < 6; i++ {
			start := time.Now()
			svc.Login(ctx, email, "senha-errada-qualquer-12", fmt.Sprintf("10.1.%d.%d", i, len(email)), "ua") // IP novo: sem bloqueio
			if d := time.Since(start); d < min {
				min = d
			}
		}
		return min
	}
	existing, unknown := best("real@exemplo.com"), best("fantasma@exemplo.com")
	disabled := best("nao-e-um-email")
	ratio := float64(unknown) / float64(existing)
	if ratio < 0.6 || ratio > 1.6 {
		t.Errorf("tempo de resposta distingue contas: existente=%v inexistente=%v (razão %.2f)", existing, unknown, ratio)
	}
	t.Logf("existente=%v inexistente=%v e-mail malformado=%v", existing, unknown, disabled)
	if float64(disabled)/float64(existing) < 0.6 {
		t.Errorf("e-mail malformado responde rápido demais (%v vs %v): revelaria validação prévia", disabled, existing)
	}
}

// Segunda linha de defesa: mesmo que a conta seja desativada por fora da API (SQL direto, outra ferramenta),
// sem revogar as sessões, uma sessão existente NÃO pode continuar valendo.
func TestSessionOfAnAccountDeactivatedOutsideTheAPIIsRejected(t *testing.T) {
	f := newFx(t)
	u := f.user("ana@exemplo.com", users.RoleAdmin)
	f.user("outro@exemplo.com", users.RoleAdmin)
	res, _ := f.login("ana@exemplo.com", pw, "10.0.0.1")
	if _, _, err := f.svc.ValidateSession(ctx, res.Session.Token); err != nil {
		t.Fatal(err)
	}
	f.pool.Exec(ctx, `UPDATE users SET is_active = false WHERE id = $1`, u.ID) // sem tocar em sessions
	if f.count(`SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL`) != 0 {
		t.Fatal("premissa: a sessão não foi revogada")
	}
	if _, _, err := f.svc.ValidateSession(ctx, res.Session.Token); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Errorf("sessão de conta desativada por fora da API: %v", err)
	}
	if f.svc.SessionValid(ctx, auth.Principal{Via: auth.ViaSession, SessionID: res.Session.ID}) {
		t.Error("SessionValid (streams SSE) também deve recusar")
	}
}
