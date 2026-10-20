package servers

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/events"
)

// StatusEvent é o evento server.status_changed. Serve a duas mudanças: do estado administrativo
// (status/previous_status) e da conectividade (connection_status/previous_connection_status).
type StatusEvent struct {
	ServerID                 string    `json:"server_id"`
	Name                     string    `json:"name"`
	Status                   string    `json:"status"`
	PreviousStatus           string    `json:"previous_status,omitempty"`
	ConnectionStatus         string    `json:"connection_status"`
	PreviousConnectionStatus string    `json:"previous_connection_status,omitempty"`
	At                       time.Time `json:"at"`
}

const connectivityLockID int64 = 0x5345434e // "SECN"

// ConnectivityMonitor detecta as TRANSIÇÕES online/offline (a conectividade é calculada pelo tempo,
// então ninguém "escreve" a queda): compara com o último estado observado (servers.connection_state)
// e publica server.status_changed.
type ConnectivityMonitor struct {
	Pool    *pgxpool.Pool
	Timeout time.Duration
	Now     func() time.Time
}

func (m *ConnectivityMonitor) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// Tick atualiza os estados e publica as transições, numa transação, sob lock (uma instância por vez).
func (m *ConnectivityMonitor) Tick(ctx context.Context) error {
	tx, err := m.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, connectivityLockID).Scan(&got); err != nil {
		return err
	}
	if !got {
		return nil
	}
	now := m.now()
	rows, err := tx.Query(ctx, `WITH calc AS (
			SELECT id, name, status, connection_state AS old,
			       CASE WHEN last_seen_at IS NULL THEN 'unknown'
			            WHEN last_seen_at >= $1::timestamptz - make_interval(secs => $2) THEN 'online'
			            ELSE 'offline' END AS new
			FROM servers WHERE deleted_at IS NULL)
		UPDATE servers s SET connection_state = c.new FROM calc c
		WHERE s.id = c.id AND c.old <> c.new
		RETURNING s.id::text, c.name, c.status, c.old, c.new`, now, m.Timeout.Seconds())
	if err != nil {
		return err
	}
	var changes []StatusEvent
	for rows.Next() {
		var e StatusEvent
		if err := rows.Scan(&e.ServerID, &e.Name, &e.Status, &e.PreviousConnectionStatus, &e.ConnectionStatus); err != nil {
			rows.Close()
			return err
		}
		e.At = now
		changes = append(changes, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// todas as escritas em servers terminaram: agora os eventos (por último)
	for _, e := range changes {
		if err := events.Publish(ctx, tx, events.TypeServerStatus, e.ServerID, e); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
