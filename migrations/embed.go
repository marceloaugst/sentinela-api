// Package migrations embute as migrações SQL versionadas.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
