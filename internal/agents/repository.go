package agents

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
)

var (
	ErrServerNotFound     = errors.New("servidor não encontrado")
	ErrCredentialNotFound = errors.New("credencial não encontrada")
	ErrInvalidCredential  = errors.New("credencial inválida, expirada ou revogada")
)

// Credential nunca contém o token nem o hash.
type Credential struct {
	ID         string     `json:"id"`
	ServerID   string     `json:"server_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// Identity é o resultado da autenticação: o servidor vem SEMPRE da credencial.
type Identity struct {
	CredentialID string
	ServerID     string
	ServerStatus string
}

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const credCols = `id, server_id, created_at, expires_at, revoked_at, last_used_at`

func scanCred(row pgx.Row) (Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.ServerID, &c.CreatedAt, &c.ExpiresAt, &c.RevokedAt, &c.LastUsedAt)
	return c, err
}

// Issue gera uma credencial. O token em texto puro só é devolvido aqui, uma única vez.
// Com replace=true, as credenciais ativas anteriores são revogadas na mesma transação.
func (r *Repository) Issue(ctx context.Context, ac audit.Context, serverID string, expiresAt *time.Time, replace bool) (Credential, string, error) {
	token, hash, err := GenerateToken()
	if err != nil {
		return Credential{}, "", err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Credential{}, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM servers WHERE id = $1 AND deleted_at IS NULL FOR SHARE)`,
		serverID).Scan(&exists); err != nil {
		return Credential{}, "", err
	}
	if !exists {
		return Credential{}, "", ErrServerNotFound
	}
	revoked := int64(0)
	if replace {
		tag, err := tx.Exec(ctx, `UPDATE agent_credentials SET revoked_at = now()
			WHERE server_id = $1 AND revoked_at IS NULL`, serverID)
		if err != nil {
			return Credential{}, "", err
		}
		revoked = tag.RowsAffected()
	}
	c, err := scanCred(tx.QueryRow(ctx, `INSERT INTO agent_credentials (server_id, token_hash, expires_at)
		VALUES ($1, $2, $3) RETURNING `+credCols, serverID, hash, expiresAt))
	if err != nil {
		return Credential{}, "", err
	}
	meta := map[string]any{"credential_id": c.ID, "replaced": replace, "revoked_previous": revoked}
	if expiresAt != nil {
		meta["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if err := audit.Write(ctx, tx, ac, "agent_credential.create", "server", serverID, meta); err != nil {
		return Credential{}, "", err
	}
	return c, token, tx.Commit(ctx)
}

func (r *Repository) List(ctx context.Context, serverID string) ([]Credential, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM servers WHERE id = $1 AND deleted_at IS NULL)`,
		serverID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrServerNotFound
	}
	rows, err := r.pool.Query(ctx, `SELECT `+credCols+` FROM agent_credentials
		WHERE server_id = $1 ORDER BY created_at DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		c, err := scanCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repository) Revoke(ctx context.Context, ac audit.Context, serverID, credID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE agent_credentials SET revoked_at = now()
		WHERE id = $1 AND server_id = $2 AND revoked_at IS NULL`, credID, serverID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}
	if err := audit.Write(ctx, tx, ac, "agent_credential.revoke", "server", serverID,
		map[string]any{"credential_id": credID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Authenticate valida o hash do token: não revogado, não expirado e servidor não removido.
func (r *Repository) Authenticate(ctx context.Context, hash []byte) (Identity, error) {
	var id Identity
	err := r.pool.QueryRow(ctx, `SELECT c.id, c.server_id, s.status
		FROM agent_credentials c JOIN servers s ON s.id = c.server_id
		WHERE c.token_hash = $1 AND c.revoked_at IS NULL
		  AND (c.expires_at IS NULL OR c.expires_at > now()) AND s.deleted_at IS NULL`, hash).
		Scan(&id.CredentialID, &id.ServerID, &id.ServerStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrInvalidCredential
	}
	if err != nil {
		return Identity{}, err
	}
	// last_used_at é atualizado no máximo uma vez por minuto para evitar escrita a cada requisição.
	_, _ = r.pool.Exec(ctx, `UPDATE agent_credentials SET last_used_at = now()
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id.CredentialID)
	return id, nil
}
