// Package events implementa o stream de eventos em tempo real (SSE).
//
// Dois tipos de evento:
//   - DURÁVEIS (alertas, incidentes, status de servidor/serviço): gravados na tabela events dentro da
//     transação que causou a mudança; têm id crescente em ordem de commit e podem ser reenviados a
//     quem reconectar com Last-Event-ID.
//   - EFÊMEROS (metrics.updated): só NOTIFY, sem id e sem replay; são alta frequência e perder um
//     não importa (o próximo traz o valor atual).
package events

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Tipos de evento (o contrato com o frontend).
const (
	TypeServerStatus      = "server.status_changed"
	TypeMetricsUpdated    = "metrics.updated"
	TypeAlertTriggered    = "alert.triggered"
	TypeAlertAcknowledged = "alert.acknowledged"
	TypeAlertResolved     = "alert.resolved"
	TypeIncidentCreated   = "incident.created"
	TypeIncidentResolved  = "incident.resolved"
	TypeServiceStatus     = "service.status_changed"
	TypeResync            = "resync" // sintético: o cliente deve recarregar o estado pela API
)

// AllTypes é a lista de tipos que um cliente pode pedir em ?types=.
var AllTypes = []string{TypeServerStatus, TypeMetricsUpdated, TypeAlertTriggered, TypeAlertAcknowledged,
	TypeAlertResolved, TypeIncidentCreated, TypeIncidentResolved, TypeServiceStatus}

func ValidType(t string) bool {
	for _, x := range AllTypes {
		if x == t {
			return true
		}
	}
	return false
}

const (
	// Prefixos dos canais LISTEN/NOTIFY, que são GLOBAIS ao banco. O nome final inclui o schema atual
	// (current_schema()), para que instalações em schemas diferentes do mesmo banco não se misturem.
	channelDurablePrefix = "sentinela_events_" // payload: id do evento
	channelLivePrefix    = "sentinela_live_"   // payload: evento efêmero em JSON
	// Serializa a PUBLICAÇÃO de eventos: o lock é mantido até o commit, então o próximo publicador só
	// obtém seu id depois que o anterior confirmou. Assim os ids seguem a ordem de commit e um cursor
	// por id nunca "pula" um evento que ainda estava em transação.
	publishLockID int64 = 0x53454556 // "SEEV"
)

// Event é o que trafega no stream. Data nunca contém segredos, URLs de alvo, tokens ou hostnames.
type Event struct {
	ID       int64           `json:"id,omitempty"` // 0 = efêmero
	Type     string          `json:"type"`
	Time     time.Time       `json:"time"`
	Data     json.RawMessage `json:"data"`
	ServerID string          `json:"-"`
}

func (e Event) Durable() bool { return e.ID > 0 }

// Execer é satisfeito por pgx.Tx e *pgxpool.Pool.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Publish grava um evento durável NA TRANSAÇÃO do chamador e agenda o NOTIFY (entregue no commit).
//
// REGRA DE ORDEM: chame Publish por ÚLTIMO na transação — depois de todas as escritas que possam
// disputar linhas com outras transações. Ele toma um lock global até o commit; tomá-lo cedo e depois
// esperar uma linha travada por quem também publica abriria espaço para deadlock.
func Publish(ctx context.Context, tx pgx.Tx, typ, serverID string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, publishLockID); err != nil {
		return err
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO events (type, server_id, data) VALUES ($1, NULLIF($2, '')::uuid, $3) RETURNING id`,
		typ, serverID, raw).Scan(&id); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT pg_notify($1 || current_schema(), $2)`, channelDurablePrefix, strconv.FormatInt(id, 10))
	return err
}

type livePayload struct {
	Type     string          `json:"type"`
	ServerID string          `json:"server_id"`
	Time     time.Time       `json:"time"`
	Data     json.RawMessage `json:"data"`
}

// PublishLive envia um evento efêmero (sem persistência). Melhor esforço.
func PublishLive(ctx context.Context, ex Execer, typ, serverID string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	p, err := json.Marshal(livePayload{Type: typ, ServerID: serverID, Time: time.Now().UTC(), Data: raw})
	if err != nil {
		return err
	}
	if len(p) > 7000 { // limite do NOTIFY é 8000 bytes
		return errors.New("evento efêmero grande demais")
	}
	_, err = ex.Exec(ctx, `SELECT pg_notify($1 || current_schema(), $2)`, channelLivePrefix, string(p))
	return err
}

// Throttle limita a frequência por chave (ex.: metrics.updated por servidor).
type Throttle struct {
	mu   sync.Mutex
	last map[string]time.Time
	min  time.Duration
	Now  func() time.Time
}

func NewThrottle(min time.Duration) *Throttle {
	return &Throttle{last: map[string]time.Time{}, min: min, Now: time.Now}
}

func (t *Throttle) Allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.Now()
	if len(t.last) > 10000 { // limita a memória: descarta entradas antigas
		for k, v := range t.last {
			if now.Sub(v) > t.min {
				delete(t.last, k)
			}
		}
	}
	if v, ok := t.last[key]; ok && now.Sub(v) < t.min {
		return false
	}
	t.last[key] = now
	return true
}
