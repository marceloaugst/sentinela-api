package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/events"
)

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const cols = `id, server_id, name, service_type, target, config, status, last_checked_at, last_error,
	last_latency_ms, last_status_code, consecutive_failures, status_changed_at, created_at, updated_at`

func scan(row pgx.Row) (Service, error) {
	var s Service
	var cfg []byte
	err := row.Scan(&s.ID, &s.ServerID, &s.Name, &s.Type, &s.Target, &cfg, &s.Status, &s.LastCheckedAt, &s.LastError,
		&s.LastLatencyMS, &s.LastStatusCode, &s.ConsecutiveFailures, &s.StatusChangedAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(cfg, &s.Config); err != nil {
		return s, fmt.Errorf("config do serviço %s: %w", s.ID, err)
	}
	return s, nil
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (r *Repository) Create(ctx context.Context, ac audit.Context, in CreateInput, cfg Config) (Service, error) {
	raw, _ := json.Marshal(cfg)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Service{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM servers WHERE id = $1 AND deleted_at IS NULL FOR SHARE)`, in.ServerID).Scan(&ok); err != nil {
		return Service{}, err
	}
	if !ok {
		return Service{}, ErrServerNotFound
	}
	s, err := scan(tx.QueryRow(ctx, `INSERT INTO monitored_services (server_id, name, service_type, target, config)
		VALUES ($1,$2,$3,$4,$5) RETURNING `+cols, in.ServerID, in.Name, in.Type, in.Target, raw))
	if isUnique(err) {
		return Service{}, ErrConflict
	}
	if err != nil {
		return Service{}, err
	}
	if err := audit.Write(ctx, tx, ac, "service.create", "service", s.ID,
		map[string]any{"server_id": s.ServerID, "name": s.Name, "type": s.Type, "target": s.Target}); err != nil {
		return Service{}, err
	}
	return s, tx.Commit(ctx)
}

func (r *Repository) Get(ctx context.Context, id string) (Service, error) {
	s, err := scan(r.pool.QueryRow(ctx, `SELECT `+cols+` FROM monitored_services WHERE id = $1 AND deleted_at IS NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Service{}, ErrNotFound
	}
	return s, err
}

func (r *Repository) Update(ctx context.Context, ac audit.Context, id string, in UpdateInput, cfg Config) (Service, error) {
	raw, _ := json.Marshal(cfg)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Service{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// next_check_at = now(): alvo/critérios alterados são reverificados logo (serviços http).
	s, err := scan(tx.QueryRow(ctx, `UPDATE monitored_services SET
			name = COALESCE($2, name), target = COALESCE($3, target), config = $4,
			next_check_at = now(), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL RETURNING `+cols, id, in.Name, in.Target, raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return Service{}, ErrNotFound
	}
	if isUnique(err) {
		return Service{}, ErrConflict
	}
	if err != nil {
		return Service{}, err
	}
	meta := map[string]any{}
	if in.Name != nil {
		meta["name"] = *in.Name
	}
	if in.Target != nil {
		meta["target"] = *in.Target
	}
	if in.Config != nil {
		meta["config_changed"] = true
	}
	if err := audit.Write(ctx, tx, ac, "service.update", "service", id, meta); err != nil {
		return Service{}, err
	}
	return s, tx.Commit(ctx)
}

func (r *Repository) Delete(ctx context.Context, ac audit.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE monitored_services SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := audit.Write(ctx, tx, ac, "service.delete", "service", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type ListParams struct {
	Page, PerPage int
	ServerID      string
	Status        string
	Type          string
	Query         string
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (r *Repository) List(ctx context.Context, p ListParams) ([]Service, int, error) {
	where := []string{"deleted_at IS NULL"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.ServerID != "" {
		add("server_id = ?", p.ServerID)
	}
	if p.Status != "" {
		add("status = ?", p.Status)
	}
	if p.Type != "" {
		add("service_type = ?", p.Type)
	}
	if p.Query != "" {
		add("(name ILIKE ? OR target ILIKE ?)", "%"+escapeLike(p.Query)+"%")
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM monitored_services WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	rows, err := r.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM monitored_services WHERE %s ORDER BY lower(name), id LIMIT $%d OFFSET $%d`,
		cols, w, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Service{}
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// ClaimDue reserva até `limit` verificações http vencidas. A reserva avança next_check_at
// para o próximo ciclo na mesma transação (FOR UPDATE SKIP LOCKED): várias instâncias não
// verificam o mesmo serviço, e se a instância cair o serviço é retomado no ciclo seguinte.
func (r *Repository) ClaimDue(ctx context.Context, limit int) ([]Service, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := tx.Query(ctx, `SELECT `+prefixCols("m")+` FROM monitored_services m
		JOIN servers s ON s.id = m.server_id AND s.deleted_at IS NULL AND s.status <> 'disabled'
		WHERE m.deleted_at IS NULL AND m.service_type = 'http' AND m.next_check_at <= now()
		ORDER BY m.next_check_at LIMIT $1 FOR UPDATE OF m SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	var out []Service
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, s := range out {
		iv := s.Config.IntervalSeconds
		if iv < 10 {
			iv = 60
		}
		if _, err := tx.Exec(ctx, `UPDATE monitored_services SET next_check_at = now() + make_interval(secs => $2) WHERE id = $1`, s.ID, iv); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit(ctx)
}

func prefixCols(p string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// StatusEvent é o evento service.status_changed (sem alvo, erro ou outros detalhes).
type StatusEvent struct {
	ServiceID      string    `json:"service_id"`
	ServerID       string    `json:"server_id"`
	ServerName     string    `json:"server_name"`
	Name           string    `json:"name"`
	Type           string    `json:"service_type"`
	PreviousStatus string    `json:"previous_status"`
	Status         string    `json:"status"`
	CheckedAt      time.Time `json:"checked_at"`
}

// record grava o resultado de uma verificação numa transação: trava o serviço, ignora resultados mais
// antigos que o gravado e, se o estado mudou, publica service.status_changed (por último).
// serverID/types restringem a escrita (agentes só alteram serviços do próprio servidor e de tipos locais).
func (r *Repository) record(ctx context.Context, id string, serverID *string, types []string, res Result, at time.Time) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var prev, name, typ, srvID, srvName string
	err = tx.QueryRow(ctx, `SELECT m.status, m.name, m.service_type, m.server_id::text, s.name
		FROM monitored_services m JOIN servers s ON s.id = m.server_id
		WHERE m.id = $1 AND ($2::uuid IS NULL OR m.server_id = $2) AND m.deleted_at IS NULL
		  AND ($3::text[] IS NULL OR cardinality($3::text[]) = 0 OR m.service_type = ANY($3::text[]))
		  AND (m.last_checked_at IS NULL OR m.last_checked_at <= $4)
		FOR UPDATE OF m`, id, serverID, types, at).Scan(&prev, &name, &typ, &srvID, &srvName)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE monitored_services SET
			status = $2, last_checked_at = $3, last_error = NULLIF($4, ''), last_latency_ms = $5, last_status_code = $6,
			consecutive_failures = CASE WHEN $2 = 'down' THEN consecutive_failures + 1 ELSE 0 END,
			status_changed_at = CASE WHEN status IS DISTINCT FROM $2 THEN $3 ELSE status_changed_at END
		WHERE id = $1`, id, res.Status, at, SanitizeError(res.Error), res.LatencyMS, res.StatusCode); err != nil {
		return false, err
	}
	if prev != res.Status {
		if err := events.Publish(ctx, tx, events.TypeServiceStatus, srvID, StatusEvent{
			ServiceID: id, ServerID: srvID, ServerName: srvName, Name: name, Type: typ,
			PreviousStatus: prev, Status: res.Status, CheckedAt: at,
		}); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

// RecordResult grava o resultado de uma verificação central (http).
func (r *Repository) RecordResult(ctx context.Context, id string, serverID *string, res Result, at time.Time) (bool, error) {
	return r.record(ctx, id, serverID, nil, res, at)
}
