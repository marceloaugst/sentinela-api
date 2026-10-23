package svcactions

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/discovery"
	"sentinela/internal/dockerhost"
	"sentinela/internal/procs"
)

var (
	ErrNotFound      = errors.New("comando não encontrado")
	ErrNoDiscovery   = errors.New("serviço não encontrado neste servidor")
	ErrNotActionable = errors.New("ação não permitida para o estado atual do serviço")
	ErrBusy          = errors.New("já existe um comando em andamento para este serviço")
	ErrInvalidState  = errors.New("o estado do comando não permite esta operação")
)

type Repository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const cols = `c.id, c.server_id, c.service_key, c.unit, c.target, c.action, c.status, c.requested_by, c.requested_actor,
	c.message, c.created_at, c.started_at, c.finished_at`

func scan(row pgx.Row) (Command, error) {
	var c Command
	err := row.Scan(&c.ID, &c.ServerID, &c.ServiceKey, &c.Unit, &c.Target, &c.Action, &c.Status, &c.RequestedBy, &c.Actor,
		&c.Message, &c.CreatedAt, &c.StartedAt, &c.FinishedAt)
	if c.ServiceKey == procs.ServiceKey {
		c.ServiceName = "Processo " + c.Unit
	} else if c.Target != "" {
		c.ServiceName = "Container " + c.Unit
	} else if spec, ok := discovery.Lookup(c.ServiceKey); ok {
		c.ServiceName = spec.Name
	} else {
		c.ServiceName = c.ServiceKey
	}
	return c, err
}

// expire encerra o que passou do prazo: pedido que o agente não pegou e comando sem resultado.
func expire(ctx context.Context, ex interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) error {
	if _, err := ex.Exec(ctx, `UPDATE service_commands SET status = 'expired', finished_at = now(),
		message = 'O agente não buscou o comando a tempo (offline ou sem permissão).'
		WHERE status = 'pending' AND created_at < now() - make_interval(secs => $1)`, PendingTTL.Seconds()); err != nil {
		return err
	}
	_, err := ex.Exec(ctx, `UPDATE service_commands SET status = 'failed', finished_at = now(),
		message = 'O agente não informou o resultado a tempo.'
		WHERE status = 'running' AND started_at < now() - make_interval(secs => $1)`, RunningTTL.Seconds())
	return err
}

// Request registra o pedido e a auditoria na mesma transação. O estado do serviço vem da última
// descoberta: a API decide o que é permitido, o agente ainda confere do lado dele.
func (r *Repository) Request(ctx context.Context, ac audit.Context, serverID, key, action string) (Command, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Command{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := expire(ctx, tx); err != nil {
		return Command{}, err
	}
	var status, source, unit string
	err = tx.QueryRow(ctx, `SELECT status, source, unit FROM service_discovery WHERE server_id = $1 AND key = $2`,
		serverID, key).Scan(&status, &source, &unit)
	if errors.Is(err, pgx.ErrNoRows) {
		return Command{}, ErrNoDiscovery
	}
	if err != nil {
		return Command{}, err
	}
	if !Contains(Allowed(key, status, source, unit), action) {
		return Command{}, ErrNotActionable
	}
	var ip *string
	if p := net.ParseIP(ac.IP); p != nil {
		s := p.String()
		ip = &s
	}
	row := tx.QueryRow(ctx, `INSERT INTO service_commands AS c (server_id, service_key, unit, action, requested_by, requested_actor, requested_ip)
		VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6, $7) RETURNING `+cols,
		serverID, key, unit, action, ac.UserID, ac.Actor, ip)
	cmd, err := scan(row)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return Command{}, ErrBusy
	}
	if err != nil {
		return Command{}, err
	}
	if err := audit.Write(ctx, tx, ac, "service."+action, "server", serverID,
		map[string]any{"service": key, "unit": unit, "command_id": cmd.ID}); err != nil {
		return Command{}, err
	}
	return cmd, tx.Commit(ctx)
}

// RequestContainer registra o pedido de iniciar/reiniciar um container Docker. O estado do container vem do último
// retrato do agente: ativo só reinicia, inativo só inicia. O pedido guarda o id completo; o agente confere de novo.
func (r *Repository) RequestContainer(ctx context.Context, ac audit.Context, serverID, containerID, action string) (Command, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Command{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := expire(ctx, tx); err != nil {
		return Command{}, err
	}
	var status string
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT status, containers FROM docker_snapshots WHERE server_id = $1`, serverID).Scan(&status, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Command{}, ErrNoDiscovery
	}
	if err != nil {
		return Command{}, err
	}
	var list []dockerhost.Container
	if err := json.Unmarshal(raw, &list); err != nil {
		return Command{}, err
	}
	var found *dockerhost.Container
	for i := range list {
		if list[i].ID == containerID {
			found = &list[i]
		}
	}
	if status != dockerhost.StatusOK || found == nil {
		return Command{}, ErrNoDiscovery
	}
	if !dockerhost.Contains(dockerhost.Allowed(found.State), action) {
		return Command{}, ErrNotActionable
	}
	var ip *string
	if p := net.ParseIP(ac.IP); p != nil {
		s := p.String()
		ip = &s
	}
	row := tx.QueryRow(ctx, `INSERT INTO service_commands AS c (server_id, service_key, unit, target, action, requested_by, requested_actor, requested_ip)
		VALUES ($1, 'docker', $2, $3, $4, NULLIF($5, '')::uuid, $6, $7) RETURNING `+cols,
		serverID, found.Name, containerID, action, ac.UserID, ac.Actor, ip)
	cmd, err := scan(row)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return Command{}, ErrBusy
	}
	if err != nil {
		return Command{}, err
	}
	if err := audit.Write(ctx, tx, ac, "docker."+action, "server", serverID,
		map[string]any{"container": containerID, "name": found.Name, "image": found.Image, "command_id": cmd.ID}); err != nil {
		return Command{}, err
	}
	return cmd, tx.Commit(ctx)
}

// RequestProcess registra o pedido de encerrar um processo (terminate = SIGTERM, kill = SIGKILL). O processo e a
// restrição vêm do último retrato do agente, que só libera processos do usuário do próprio agente; o agente confere tudo de
// novo (e prende o processo com um pidfd) antes de sinalizar. O alvo é "<pid>:<início>", então um pid reaproveitado não é atingido.
func (r *Repository) RequestProcess(ctx context.Context, ac audit.Context, serverID string, pid int, start uint64, action string) (Command, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Command{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := expire(ctx, tx); err != nil {
		return Command{}, err
	}
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT processes FROM process_snapshots WHERE server_id = $1`, serverID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Command{}, ErrNoDiscovery
	}
	if err != nil {
		return Command{}, err
	}
	var list []procs.Process
	if err := json.Unmarshal(raw, &list); err != nil {
		return Command{}, err
	}
	var found *procs.Process
	for i := range list {
		if list[i].PID == pid && list[i].StartTime == start {
			found = &list[i]
		}
	}
	if found == nil {
		return Command{}, ErrNoDiscovery
	}
	if found.Restriction != procs.RestrictNone {
		return Command{}, ErrNotActionable
	}
	var ip *string
	if p := net.ParseIP(ac.IP); p != nil {
		s := p.String()
		ip = &s
	}
	row := tx.QueryRow(ctx, `INSERT INTO service_commands AS c (server_id, service_key, unit, target, action, requested_by, requested_actor, requested_ip)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::uuid, $7, $8) RETURNING `+cols,
		serverID, procs.ServiceKey, found.Name, procs.Target(pid, start), action, ac.UserID, ac.Actor, ip)
	cmd, err := scan(row)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return Command{}, ErrBusy
	}
	if err != nil {
		return Command{}, err
	}
	if err := audit.Write(ctx, tx, ac, "process."+action, "server", serverID,
		map[string]any{"pid": pid, "name": found.Name, "user": found.User, "command_id": cmd.ID}); err != nil {
		return Command{}, err
	}
	return cmd, tx.Commit(ctx)
}

// Claim entrega ao agente os comandos pendentes do servidor e os marca como em execução.
func (r *Repository) Claim(ctx context.Context, serverID string) ([]Pending, error) {
	if err := expire(ctx, r.pool); err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, `UPDATE service_commands SET status = 'running', started_at = now()
		WHERE id IN (SELECT id FROM service_commands WHERE server_id = $1 AND status = 'pending'
		             ORDER BY created_at LIMIT 5 FOR UPDATE SKIP LOCKED)
		RETURNING id, service_key, action, target`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Pending{}
	for rows.Next() {
		var p Pending
		if err := rows.Scan(&p.ID, &p.ServiceKey, &p.Action, &p.Target); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Complete grava o resultado enviado pelo agente do servidor dono do comando.
func (r *Repository) Complete(ctx context.Context, serverID, id string, res Result) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var key, action, status, target string
	err = tx.QueryRow(ctx, `SELECT service_key, action, status, target FROM service_commands
		WHERE id = $1 AND server_id = $2 FOR UPDATE`, id, serverID).Scan(&key, &action, &status, &target)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != StatusRunning {
		return ErrInvalidState
	}
	if _, err := tx.Exec(ctx, `UPDATE service_commands SET status = $2, message = $3, finished_at = now() WHERE id = $1`,
		id, res.Status, res.Message); err != nil {
		return err
	}
	meta := map[string]any{"service": key, "action": action, "command_id": id, "result": res.Status, "message": res.Message}
	switch {
	case key == procs.ServiceKey:
		meta["process"] = target
	case target != "":
		meta["container"] = target
	}
	if err := audit.Write(ctx, tx, audit.Context{Actor: "agente"}, "service.result", "server", serverID, meta); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *Repository) Get(ctx context.Context, id string) (Command, error) {
	if err := expire(ctx, r.pool); err != nil {
		return Command{}, err
	}
	c, err := scan(r.pool.QueryRow(ctx, `SELECT `+cols+` FROM service_commands c WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Command{}, ErrNotFound
	}
	return c, err
}

// List devolve os comandos mais recentes do servidor.
func (r *Repository) List(ctx context.Context, serverID string, limit int) ([]Command, error) {
	if err := expire(ctx, r.pool); err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, `SELECT `+cols+` FROM service_commands c WHERE c.server_id = $1
		ORDER BY c.created_at DESC LIMIT $2`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Command{}
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
