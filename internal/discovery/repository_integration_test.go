//go:build integration

package discovery_test

import (
	"context"
	"testing"
	"time"

	"sentinela/internal/discovery"
	"sentinela/internal/testutil"
)

const srv = "11111111-1111-1111-1111-111111111111"

func TestReplaceAndList(t *testing.T) {
	pool := testutil.NewDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO servers (id, name, hostname) VALUES ($1, 's', 'h')`, srv); err != nil {
		t.Fatal(err)
	}
	repo := discovery.NewRepository(pool)
	t0 := time.Now().UTC().Truncate(time.Second)

	first := discovery.Report{CheckedAt: t0, Services: []discovery.Finding{
		{Key: "redis", Status: discovery.StatusNotFound},
		{Key: "ssh", Status: discovery.StatusAvailable, Source: discovery.SourceSystemd, Unit: "ssh.service"},
		{Key: "cron", Status: discovery.StatusStopped, Unit: "cron.service"},
	}}
	if err := repo.Replace(ctx, srv, first); err != nil {
		t.Fatal(err)
	}
	items, err := repo.List(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	// ordem do catálogo: ssh, cron, redis
	if len(items) != 3 || items[0].Key != "ssh" || items[1].Key != "cron" || items[2].Key != "redis" {
		t.Fatalf("itens: %+v", items)
	}
	if !items[0].Available || items[0].Action != "" || items[1].Action == "" || items[2].Action == "" {
		t.Fatalf("disponibilidade/ação: %+v", items)
	}
	changed := *items[0].StatusChangedAt

	// Segundo retrato: ssh igual (status_changed_at não muda), cron vira disponível, redis some.
	second := discovery.Report{CheckedAt: t0.Add(time.Minute), Services: []discovery.Finding{
		{Key: "ssh", Status: discovery.StatusAvailable, Source: discovery.SourceSystemd, Unit: "ssh.service"},
		{Key: "cron", Status: discovery.StatusAvailable, Source: discovery.SourceSystemd, Unit: "cron.service"},
	}}
	if err := repo.Replace(ctx, srv, second); err != nil {
		t.Fatal(err)
	}
	items, _ = repo.List(ctx, srv)
	if len(items) != 2 || !items[1].Available {
		t.Fatalf("após o segundo retrato: %+v", items)
	}
	if !items[0].StatusChangedAt.Equal(changed) {
		t.Errorf("status_changed_at do ssh mudou sem mudança de status")
	}

	// Relatório atrasado não sobrescreve nem remove nada.
	if err := repo.Replace(ctx, srv, first); err != nil {
		t.Fatal(err)
	}
	items, _ = repo.List(ctx, srv)
	if len(items) != 2 || !items[1].Available {
		t.Fatalf("relatório antigo sobrescreveu: %+v", items)
	}
}
