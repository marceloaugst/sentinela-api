//go:build integration

// Package testutil oferece utilitários para testes de integração.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/database"
	"sentinela/migrations"
)

// IsolatedURL cria um schema exclusivo para o teste e devolve uma URL cujo search_path
// aponta para ele. Isso permite que pacotes de teste rodem em paralelo no mesmo banco.
// O schema é removido ao fim do teste.
func IsolatedURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL não definida")
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("conectar ao banco de teste: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(c, base)
		if err != nil {
			return
		}
		defer conn.Close(c)
		_, _ = conn.Exec(c, "DROP SCHEMA "+schema+" CASCADE")
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// NewDB devolve um pool em schema isolado, com todas as migrações aplicadas.
func NewDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, _ := NewDBURL(t)
	return pool
}

// NewDBURL é como NewDB e também devolve a URL (necessária a conexões dedicadas, como o LISTEN do hub).
func NewDBURL(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	url := IsolatedURL(t)
	pool, err := database.NewPool(ctx, url, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	m, err := database.NewMigrator(pool, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return pool, url
}
