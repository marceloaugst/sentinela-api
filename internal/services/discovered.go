package services

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Discovered é o estado de um serviço do sistema reportado pela descoberta automática.
type Discovered struct {
	Key    string // chave do catálogo (ssh, nginx, redis...)
	Name   string // nome para exibição
	Target string // unidade systemd ou, na falta dela, a chave
	Up     bool
	Reason string // motivo quando !Up (texto fixo da API, nunca vindo do agente)
}

// SyncDiscovered espelha a descoberta em monitored_services para que alertas e incidentes valham
// para os serviços achados sozinhos. Regras:
//   - só passa a monitorar um serviço depois que ele foi visto disponível; quem nunca existiu no
//     servidor (ex.: Redis não instalado) não gera alerta;
//   - depois disso, parado/sumido vira "down" (e o alerta service_down cuida do resto);
//   - serviço descoberto que o usuário excluiu não é recriado.
func (r *Repository) SyncDiscovered(ctx context.Context, serverID string, items []Discovered, at time.Time) error {
	for _, it := range items {
		var id string
		var deleted bool
		err := r.pool.QueryRow(ctx, `SELECT id, deleted_at IS NOT NULL FROM monitored_services
			WHERE server_id = $1 AND discovery_key = $2`, serverID, it.Key).Scan(&id, &deleted)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if !it.Up {
				continue
			}
			// DO NOTHING também cobre nome já usado por um serviço manual: nesse caso não monitora.
			err = r.pool.QueryRow(ctx, `INSERT INTO monitored_services (server_id, name, service_type, target, config, discovery_key)
				VALUES ($1, $2, 'discovered', $3, '{"timeout_seconds":3,"interval_seconds":60}', $4)
				ON CONFLICT DO NOTHING RETURNING id`, serverID, it.Name+" (automático)", it.Target, it.Key).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
		case err != nil:
			return err
		case deleted:
			continue
		}
		res := Result{Status: StatusDown, Error: it.Reason}
		if it.Up {
			res = Result{Status: StatusUp}
		}
		if _, err := r.record(ctx, id, &serverID, []string{TypeDiscovered}, res, at); err != nil {
			return err
		}
	}
	return nil
}
