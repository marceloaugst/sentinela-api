// Package users gerencia contas de usuário e seus papéis.
package users

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/passwords"
	"sentinela/internal/validation"
)

var (
	ErrNotFound  = errors.New("usuário não encontrado")
	ErrConflict  = errors.New("já existe um usuário com esse e-mail")
	ErrLastAdmin = errors.New("não é possível remover o último administrador ativo")
)

// Papéis em ordem crescente de privilégio.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

func ValidRole(r string) bool { return r == RoleViewer || r == RoleOperator || r == RoleAdmin }

type User struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Email             string     `json:"email"`
	Role              string     `json:"role"`
	IsActive          bool       `json:"is_active"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastLoginAt       *time.Time `json:"last_login_at"`
	PasswordChangedAt time.Time  `json:"password_changed_at"`
}

// Credentials inclui o hash e NUNCA é serializado para a API.
type Credentials struct {
	User
	PasswordHash string
}

var emailRe = regexp.MustCompile(`^[^@\s<>()\[\]\\,;:"]+@[^@\s<>()\[\]\\,;:"]+\.[^@\s<>()\[\]\\,;:"]+$`)

// NormalizeEmail aplica trim e minúsculas; ok=false se o formato for inválido.
func NormalizeEmail(e string) (string, bool) {
	e = strings.ToLower(strings.TrimSpace(e))
	return e, len(e) <= 254 && emailRe.MatchString(e)
}

type CreateInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func (in *CreateInput) Validate() validation.Problems {
	var p validation.Problems
	in.Name = p.Text("name", in.Name, 1, 120)
	if e, ok := NormalizeEmail(in.Email); ok {
		in.Email = e
	} else {
		p.Add("email", "e-mail inválido")
	}
	if !ValidRole(in.Role) {
		p.Add("role", "deve ser viewer, operator ou admin")
	}
	for _, m := range passwords.Validate(in.Password, in.Email, in.Name) {
		p.Add("password", m)
	}
	return p
}

type UpdateInput struct {
	Name     *string `json:"name"`
	Email    *string `json:"email"`
	Role     *string `json:"role"`
	IsActive *bool   `json:"is_active"`
	Password *string `json:"password"`
}

// Validate valida o patch; email/nome efetivos são usados na política de senha.
func (in *UpdateInput) Validate(cur User) validation.Problems {
	var p validation.Problems
	if *in == (UpdateInput{}) {
		p.Add("body", "informe ao menos um campo")
		return p
	}
	name, email := cur.Name, cur.Email
	if in.Name != nil {
		n := p.Text("name", *in.Name, 1, 120)
		in.Name, name = &n, n
	}
	if in.Email != nil {
		if e, ok := NormalizeEmail(*in.Email); ok {
			in.Email, email = &e, e
		} else {
			p.Add("email", "e-mail inválido")
		}
	}
	if in.Role != nil && !ValidRole(*in.Role) {
		p.Add("role", "deve ser viewer, operator ou admin")
	}
	if in.Password != nil {
		for _, m := range passwords.Validate(*in.Password, email, name) {
			p.Add("password", m)
		}
	}
	return p
}

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const cols = `id, name, email, role, is_active, created_at, updated_at, last_login_at, password_changed_at`

func scan(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt, &u.PasswordChangedAt)
	return u, err
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

type NewUser struct {
	Name, Email, Role, PasswordHash string
}

// Create grava o usuário. O hash já vem pronto (a senha em texto puro nunca chega ao repositório).
func (r *Repository) Create(ctx context.Context, ac audit.Context, in NewUser) (User, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email)) // defesa em profundidade: a unicidade é por e-mail normalizado
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	u, err := scan(tx.QueryRow(ctx, `INSERT INTO users (name, email, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING `+cols,
		in.Name, in.Email, in.PasswordHash, in.Role))
	if isUnique(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, err
	}
	if err := audit.Write(ctx, tx, ac, "user.create", "user", u.ID, map[string]any{"email": u.Email, "role": u.Role}); err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

func (r *Repository) Get(ctx context.Context, id string) (User, error) {
	u, err := scan(r.pool.QueryRow(ctx, `SELECT `+cols+` FROM users WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (r *Repository) GetCredentialsByEmail(ctx context.Context, email string) (Credentials, error) {
	var c Credentials
	err := r.pool.QueryRow(ctx, `SELECT `+cols+`, password_hash FROM users WHERE email = $1`, email).
		Scan(&c.ID, &c.Name, &c.Email, &c.Role, &c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt, &c.PasswordChangedAt, &c.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credentials{}, ErrNotFound
	}
	return c, err
}

func (r *Repository) GetCredentials(ctx context.Context, id string) (Credentials, error) {
	var c Credentials
	err := r.pool.QueryRow(ctx, `SELECT `+cols+`, password_hash FROM users WHERE id = $1`, id).
		Scan(&c.ID, &c.Name, &c.Email, &c.Role, &c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt, &c.PasswordChangedAt, &c.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credentials{}, ErrNotFound
	}
	return c, err
}

func (r *Repository) Count(ctx context.Context) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

type ListParams struct {
	Page, PerPage int
	Query         string
	Role          string
	Active        *bool
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (r *Repository) List(ctx context.Context, p ListParams) ([]User, int, error) {
	where := []string{"true"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.Query != "" {
		add("(name ILIKE ? OR email ILIKE ?)", "%"+escapeLike(p.Query)+"%")
	}
	if p.Role != "" {
		add("role = ?", p.Role)
	}
	if p.Active != nil {
		add("is_active = ?", *p.Active)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM users WHERE %s ORDER BY lower(name), id LIMIT $%d OFFSET $%d`,
		cols, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

type UpdateParams struct {
	Name, Email, Role *string
	IsActive          *bool
	PasswordHash      *string
}

// Update aplica o patch. Regras:
//   - nunca deixa o sistema sem um administrador ativo (ErrLastAdmin);
//   - desativar o usuário ou trocar a senha revoga TODAS as sessões dele, na mesma transação.
//
// Devolve o usuário atualizado e quantas sessões foram revogadas.
func (r *Repository) Update(ctx context.Context, ac audit.Context, id string, p UpdateParams) (User, int64, error) {
	if p.Email != nil {
		e := strings.ToLower(strings.TrimSpace(*p.Email))
		p.Email = &e
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Trava todos os administradores ativos: duas alterações concorrentes não podem remover os dois últimos.
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE role = 'admin' AND is_active ORDER BY id FOR UPDATE`)
	if err != nil {
		return User{}, 0, err
	}
	activeAdmins := map[string]bool{}
	for rows.Next() {
		var aid string
		if err := rows.Scan(&aid); err != nil {
			rows.Close()
			return User{}, 0, err
		}
		activeAdmins[aid] = true
	}
	rows.Close()

	var curRole string
	var curActive bool
	if err := tx.QueryRow(ctx, `SELECT role, is_active FROM users WHERE id = $1 FOR UPDATE`, id).Scan(&curRole, &curActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, 0, ErrNotFound
		}
		return User{}, 0, err
	}
	newRole, newActive := curRole, curActive
	if p.Role != nil {
		newRole = *p.Role
	}
	if p.IsActive != nil {
		newActive = *p.IsActive
	}
	wasAdmin, willBeAdmin := curActive && curRole == RoleAdmin, newActive && newRole == RoleAdmin
	if wasAdmin && !willBeAdmin {
		others := 0
		for aid := range activeAdmins {
			if aid != id {
				others++
			}
		}
		if others == 0 {
			return User{}, 0, ErrLastAdmin
		}
	}

	u, err := scan(tx.QueryRow(ctx, `UPDATE users SET
			name = COALESCE($2, name), email = COALESCE($3, email), role = COALESCE($4, role),
			is_active = COALESCE($5, is_active), password_hash = COALESCE($6, password_hash),
			password_changed_at = CASE WHEN $6::text IS NULL THEN password_changed_at ELSE now() END,
			updated_at = now()
		WHERE id = $1 RETURNING `+cols, id, p.Name, p.Email, p.Role, p.IsActive, p.PasswordHash))
	if isUnique(err) {
		return User{}, 0, ErrConflict
	}
	if err != nil {
		return User{}, 0, err
	}

	var revoked int64
	reason := ""
	switch {
	case p.IsActive != nil && !*p.IsActive && curActive:
		reason = "user_deactivated"
	case p.PasswordHash != nil:
		reason = "password_changed"
	}
	if reason != "" {
		tag, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE user_id = $1 AND revoked_at IS NULL`, id, reason)
		if err != nil {
			return User{}, 0, err
		}
		revoked = tag.RowsAffected()
	}

	meta := map[string]any{"revoked_sessions": revoked}
	if p.Name != nil {
		meta["name"] = *p.Name
	}
	if p.Email != nil {
		meta["email"] = *p.Email
	}
	if p.Role != nil {
		meta["role"] = *p.Role
		meta["previous_role"] = curRole
	}
	if p.IsActive != nil {
		meta["is_active"] = *p.IsActive
	}
	meta["credentials_updated"] = p.PasswordHash != nil // nunca o valor da senha
	if err := audit.Write(ctx, tx, ac, "user.update", "user", id, meta); err != nil {
		return User{}, 0, err
	}
	return u, revoked, tx.Commit(ctx)
}

// RevokeSessions revoga todas as sessões ativas do usuário (opcionalmente poupando uma).
func (r *Repository) RevokeSessions(ctx context.Context, ac audit.Context, userID, reason, exceptSession string) (int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&ok); err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrNotFound
	}
	tag, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now(), revoked_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL AND ($3 = '' OR id::text <> $3)`, userID, reason, exceptSession)
	if err != nil {
		return 0, err
	}
	if err := audit.Write(ctx, tx, ac, "user.sessions_revoke", "user", userID, map[string]any{"revoked_sessions": tag.RowsAffected(), "reason": reason}); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}

// Touch registra o último login e, se informado, troca o hash (rehash transparente após subir o custo).
func (r *Repository) MarkLogin(ctx context.Context, id string, now time.Time, newHash string) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET last_login_at = $2, password_hash = CASE WHEN $3 = '' THEN password_hash ELSE $3 END WHERE id = $1`, id, now, newHash)
	return err
}
