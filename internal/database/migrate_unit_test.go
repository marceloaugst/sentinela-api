package database

import (
	"testing"
	"testing/fstest"
)

func TestLoadMigrationsOrderedAndPaired(t *testing.T) {
	fsys := fstest.MapFS{
		"0002_b.up.sql":   {Data: []byte("SELECT 2")},
		"0002_b.down.sql": {Data: []byte("SELECT -2")},
		"0001_a.up.sql":   {Data: []byte("SELECT 1")},
		"0001_a.down.sql": {Data: []byte("SELECT -1")},
		"README.md":       {Data: []byte("ignorado")},
	}
	migs, err := LoadMigrations(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(migs) != 2 || migs[0].Version != 1 || migs[1].Name != "b" {
		t.Errorf("migrações: %+v", migs)
	}
}

func TestLoadMigrationsErrors(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"sem down":      {"0001_a.up.sql": {Data: []byte("x")}},
		"sem sufixo":    {"0001_a.sql": {Data: []byte("x")}},
		"nome inválido": {"abc.up.sql": {Data: []byte("x")}, "abc.down.sql": {Data: []byte("x")}},
		"lacuna": {
			"0001_a.up.sql": {Data: []byte("x")}, "0001_a.down.sql": {Data: []byte("x")},
			"0003_c.up.sql": {Data: []byte("x")}, "0003_c.down.sql": {Data: []byte("x")},
		},
		"nomes divergentes": {
			"0001_a.up.sql": {Data: []byte("x")}, "0001_b.down.sql": {Data: []byte("x")},
		},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadMigrations(fsys); err == nil {
				t.Error("esperava erro")
			}
		})
	}
}
