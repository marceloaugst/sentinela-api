// Package servers implementa o cadastro de servidores monitorados.
package servers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/events"
	"sentinela/internal/validation"
)

var (
	ErrNotFound = errors.New("servidor não encontrado")
	ErrConflict = errors.New("já existe um servidor com esse nome")
)

// Estados administrativos. A conectividade é calculada e nunca gravada.
const (
	StatusActive      = "active"
	StatusMaintenance = "maintenance"
	StatusDisabled    = "disabled"
)

const (
	ConnOnline  = "online"
	ConnOffline = "offline"
	ConnUnknown = "unknown" // nunca recebeu comunicação
)

type Server struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	Hostname               string     `json:"hostname"`
	OperatingSystem        *string    `json:"operating_system"`
	OperatingSystemVersion *string    `json:"operating_system_version"`
	Architecture           *string    `json:"architecture"`
	AgentVersion           *string    `json:"agent_version"`
	Status                 string     `json:"status"`
	ConnectionStatus       string     `json:"connection_status"`
	LastSeenAt             *time.Time `json:"last_seen_at"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type Disk struct {
	MountPoint     string    `json:"mount_point"`
	Filesystem     *string   `json:"filesystem"`
	TotalBytes     int64     `json:"total_bytes"`
	UsedBytes      int64     `json:"used_bytes"`
	AvailableBytes int64     `json:"available_bytes"`
	UsedPercent    float64   `json:"used_percent"`
	CollectedAt    time.Time `json:"collected_at"`
}

type CreateInput struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

func (in *CreateInput) Validate() validation.Problems {
	var p validation.Problems
	in.Name = p.Text("name", in.Name, 1, 120)
	in.Hostname = p.Hostname("hostname", in.Hostname)
	return p
}

type UpdateInput struct {
	Name     *string `json:"name"`
	Hostname *string `json:"hostname"`
	Status   *string `json:"status"`
}

func (in *UpdateInput) Validate() validation.Problems {
	var p validation.Problems
	if in.Name == nil && in.Hostname == nil && in.Status == nil {
		p.Add("body", "informe ao menos um campo (name, hostname ou status)")
		return p
	}
	if in.Name != nil {
		v := p.Text("name", *in.Name, 1, 120)
		in.Name = &v
	}
	if in.Hostname != nil {
		v := p.Hostname("hostname", *in.Hostname)
		in.Hostname = &v
	}
	if in.Status != nil {
		switch *in.Status {
		case StatusActive, StatusMaintenance, StatusDisabled:
		default:
			p.Add("status", "deve ser active, maintenance ou disabled")
		}
	}
	return p
}

// ListParams já validados pelo handler.
type ListParams struct {
	Page, PerPage int
	Query         string
	Status        string // administrativo
	Connection    string // online|offline|unknown
	Sort          string
	Desc          bool
}

var sortColumns = map[string]string{
	"name":         "lower(name)",
	"hostname":     "lower(hostname)",
	"created_at":   "created_at",
	"last_seen_at": "last_seen_at",
	"status":       "status",
}

func SortAllowed(s string) bool { _, ok := sortColumns[s]; return ok }

type Repository struct {
	pool             *pgxpool.Pool
	heartbeatTimeout time.Duration
}

func NewRepository(pool *pgxpool.Pool, heartbeatTimeout time.Duration) *Repository {
	return &Repository{pool: pool, heartbeatTimeout: heartbeatTimeout}
}

func (r *Repository) connExpr() string {
	return fmt.Sprintf(`CASE WHEN last_seen_at IS NULL THEN 'unknown'
		WHEN last_seen_at >= now() - interval '%d seconds' THEN 'online' ELSE 'offline' END`,
		int(r.heartbeatTimeout.Seconds()))
}

func (r *Repository) cols() string {
	return `id, name, hostname, operating_system, operating_system_version, architecture,
		agent_version, status, last_seen_at, created_at, updated_at, ` + r.connExpr()
}

func scan(row pgx.Row) (Server, error) {
	var s Server
	err := row.Scan(&s.ID, &s.Name, &s.Hostname, &s.OperatingSystem, &s.OperatingSystemVersion,
		&s.Architecture, &s.AgentVersion, &s.Status, &s.LastSeenAt, &s.CreatedAt, &s.UpdatedAt, &s.ConnectionStatus)
	return s, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (r *Repository) Create(ctx context.Context, ac audit.Context, in CreateInput) (Server, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Server{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	s, err := scan(tx.QueryRow(ctx,
		`INSERT INTO servers (name, hostname) VALUES ($1, $2) RETURNING `+r.cols(), in.Name, in.Hostname))
	if isUniqueViolation(err) {
		return Server{}, ErrConflict
	}
	if err != nil {
		return Server{}, err
	}
	if err := audit.Write(ctx, tx, ac, "server.create", "server", s.ID,
		map[string]any{"name": s.Name, "hostname": s.Hostname}); err != nil {
		return Server{}, err
	}
	return s, tx.Commit(ctx)
}

func (r *Repository) Get(ctx context.Context, id string) (Server, error) {
	s, err := scan(r.pool.QueryRow(ctx,
		`SELECT `+r.cols()+` FROM servers WHERE id = $1 AND deleted_at IS NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	return s, err
}

func (r *Repository) Update(ctx context.Context, ac audit.Context, id string, in UpdateInput) (Server, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Server{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var prevStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM servers WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&prevStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Server{}, ErrNotFound
		}
		return Server{}, err
	}
	s, err := scan(tx.QueryRow(ctx, `UPDATE servers SET
			name = COALESCE($2, name), hostname = COALESCE($3, hostname),
			status = COALESCE($4, status), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL RETURNING `+r.cols(), id, in.Name, in.Hostname, in.Status))
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	if isUniqueViolation(err) {
		return Server{}, ErrConflict
	}
	if err != nil {
		return Server{}, err
	}
	meta := map[string]any{}
	if in.Name != nil {
		meta["name"] = *in.Name
	}
	if in.Hostname != nil {
		meta["hostname"] = *in.Hostname
	}
	if in.Status != nil {
		meta["status"] = *in.Status
	}
	if err := audit.Write(ctx, tx, ac, "server.update", "server", id, meta); err != nil {
		return Server{}, err
	}
	if s.Status != prevStatus { // evento por ÚLTIMO (ver events.Publish)
		if err := events.Publish(ctx, tx, events.TypeServerStatus, id, StatusEvent{
			ServerID: id, Name: s.Name, Status: s.Status, PreviousStatus: prevStatus, ConnectionStatus: s.ConnectionStatus, At: time.Now().UTC(),
		}); err != nil {
			return Server{}, err
		}
	}
	return s, tx.Commit(ctx)
}

// Delete faz exclusão lógica: o histórico (métricas, alertas, incidentes) é preservado,
// as credenciais do agente são revogadas e o nome fica livre para reutilização.
func (r *Repository) Delete(ctx context.Context, ac audit.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `UPDATE servers SET deleted_at = now(), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_credentials SET revoked_at = now()
		WHERE server_id = $1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	if err := audit.Write(ctx, tx, ac, "server.delete", "server", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (r *Repository) List(ctx context.Context, p ListParams) ([]Server, int, error) {
	where := []string{"deleted_at IS NULL"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if p.Query != "" {
		add("(name ILIKE ? OR hostname ILIKE ?)", "%"+escapeLike(p.Query)+"%")
	}
	if p.Status != "" {
		add("status = ?", p.Status)
	}
	if p.Connection != "" {
		add("("+r.connExpr()+") = ?", p.Connection)
	}
	w := strings.Join(where, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM servers WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	col, ok := sortColumns[p.Sort]
	if !ok {
		col = sortColumns["name"]
	}
	dir := "ASC"
	if p.Desc {
		dir = "DESC"
	}
	args = append(args, p.PerPage, (p.Page-1)*p.PerPage)
	q := fmt.Sprintf(`SELECT %s FROM servers WHERE %s ORDER BY %s %s NULLS LAST, id LIMIT $%d OFFSET $%d`,
		r.cols(), w, col, dir, len(args)-1, len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Server{}
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

func (r *Repository) Disks(ctx context.Context, serverID string) ([]Disk, error) {
	if _, err := r.Get(ctx, serverID); err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, `SELECT mount_point, filesystem, total_bytes, used_bytes, available_bytes, collected_at
		FROM server_disks WHERE server_id = $1 ORDER BY mount_point`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Disk{}
	for rows.Next() {
		var d Disk
		if err := rows.Scan(&d.MountPoint, &d.Filesystem, &d.TotalBytes, &d.UsedBytes, &d.AvailableBytes, &d.CollectedAt); err != nil {
			return nil, err
		}
		if d.TotalBytes > 0 {
			d.UsedPercent = float64(d.UsedBytes) / float64(d.TotalBytes) * 100
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
