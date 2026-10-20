package database

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisory lock para impedir migrações concorrentes entre instâncias.
const migrationLockID int64 = 0x53454e54 // "SENT"

type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

// LoadMigrations lê arquivos NNNN_nome.up.sql / NNNN_nome.down.sql.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	byVersion := map[int]*Migration{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".sql")
		var dir string
		switch {
		case strings.HasSuffix(base, ".up"):
			dir, base = "up", strings.TrimSuffix(base, ".up")
		case strings.HasSuffix(base, ".down"):
			dir, base = "down", strings.TrimSuffix(base, ".down")
		default:
			return nil, fmt.Errorf("migração %q: sufixo .up/.down ausente", e.Name())
		}
		num, name, ok := strings.Cut(base, "_")
		v, convErr := strconv.Atoi(num)
		if !ok || convErr != nil || v < 1 {
			return nil, fmt.Errorf("migração %q: nome deve ser NNNN_descricao", e.Name())
		}
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		m := byVersion[v]
		if m == nil {
			m = &Migration{Version: v, Name: name}
			byVersion[v] = m
		} else if m.Name != name {
			return nil, fmt.Errorf("versão %d com nomes diferentes: %q e %q", v, m.Name, name)
		}
		if dir == "up" {
			m.Up = string(body)
		} else {
			m.Down = string(body)
		}
	}
	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if strings.TrimSpace(m.Up) == "" || strings.TrimSpace(m.Down) == "" {
			return nil, fmt.Errorf("migração %04d_%s precisa de .up.sql e .down.sql", m.Version, m.Name)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("sequência de versões com lacuna perto de %d", m.Version)
		}
	}
	return out, nil
}

type Migrator struct {
	pool *pgxpool.Pool
	migs []Migration
}

func NewMigrator(pool *pgxpool.Pool, fsys fs.FS) (*Migrator, error) {
	migs, err := LoadMigrations(fsys)
	if err != nil {
		return nil, err
	}
	return &Migrator{pool: pool, migs: migs}, nil
}

func (m *Migrator) withLock(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// o lock é liberado automaticamente no fim da transação
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func current(ctx context.Context, tx pgx.Tx) (int, error) {
	var v int
	err := tx.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM schema_migrations").Scan(&v)
	return v, err
}

// Version retorna a versão atualmente aplicada.
func (m *Migrator) Version(ctx context.Context) (int, error) {
	var v int
	err := m.withLock(ctx, func(tx pgx.Tx) (e error) { v, e = current(ctx, tx); return })
	return v, err
}

// Up aplica todas as migrações pendentes, cada uma em sua transação lógica.
func (m *Migrator) Up(ctx context.Context) (applied int, err error) {
	err = m.withLock(ctx, func(tx pgx.Tx) error {
		cur, err := current(ctx, tx)
		if err != nil {
			return err
		}
		for _, mig := range m.migs {
			if mig.Version <= cur {
				continue
			}
			if _, err := tx.Exec(ctx, mig.Up); err != nil {
				return fmt.Errorf("migração %04d_%s: %w", mig.Version, mig.Name, err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version, name) VALUES ($1,$2)", mig.Version, mig.Name); err != nil {
				return err
			}
			applied++
		}
		return nil
	})
	if err != nil {
		applied = 0
	}
	return applied, err
}

// Down reverte as últimas n migrações (n <= 0 reverte todas).
func (m *Migrator) Down(ctx context.Context, n int) (reverted int, err error) {
	err = m.withLock(ctx, func(tx pgx.Tx) error {
		cur, err := current(ctx, tx)
		if err != nil {
			return err
		}
		for i := len(m.migs) - 1; i >= 0 && (n <= 0 || reverted < n); i-- {
			mig := m.migs[i]
			if mig.Version > cur {
				continue
			}
			if _, err := tx.Exec(ctx, mig.Down); err != nil {
				return fmt.Errorf("reverter %04d_%s: %w", mig.Version, mig.Name, err)
			}
			if _, err := tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", mig.Version); err != nil {
				return err
			}
			reverted++
		}
		return nil
	})
	if err != nil {
		reverted = 0
	}
	return reverted, err
}
