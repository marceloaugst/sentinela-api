// Package notifications entrega notificações de alerta por canais (Telegram) usando uma fila
// persistente (outbox) em PostgreSQL: nada se perde em reinicializações e mensagens repetidas
// são impedidas por uma chave de deduplicação única por canal.
package notifications

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	KindTriggered = "triggered"
	KindResolved  = "resolved"
	KindTest      = "test"
	KindIPBanned  = "ip_banned" // fail2ban baniu um IP
)

var severityRank = map[string]int{"info": 1, "warning": 2, "critical": 3}

// Rank devolve a ordem de gravidade (info < warning < critical); desconhecida = 0.
func Rank(sev string) int { return severityRank[sev] }

// Payload é o conteúdo persistido na fila; a mensagem de texto é montada no envio.
type Payload struct {
	Kind        string    `json:"kind"`
	ServerID    string    `json:"server_id,omitempty"`
	AlertID     string    `json:"alert_id,omitempty"`
	IncidentID  string    `json:"incident_id,omitempty"`
	ServerName  string    `json:"server_name"`
	ServiceName string    `json:"service_name,omitempty"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Priority    int       `json:"priority,omitempty"`   // 1 (P1) a 4 (P4); 0 = não informada
	Recurrence  int       `json:"recurrence,omitempty"` // incidentes anteriores iguais nas últimas 24 h
	Message     string    `json:"message"`
	At          time.Time `json:"at"`
	// Silenced: o alerta caiu numa janela de silenciamento/manutenção. Fica no registro do painel, mas não vai aos canais.
	Silenced      bool   `json:"silenced,omitempty"`
	SilenceReason string `json:"silence_reason,omitempty"`
}

func DedupKey(alertID, kind string) string { return "alert:" + alertID + ":" + kind }

// EnqueueAlert grava, NA TRANSAÇÃO do chamador, uma notificação para cada canal elegível:
// canal habilitado cujo min_severity (padrão: info, ou seja, todos) seja ≤ gravidade do alerta.
// O aviso de recuperação só vai a canais que receberam o aviso de disparo.
func EnqueueAlert(ctx context.Context, tx pgx.Tx, p Payload) error {
	if err := Record(ctx, tx, p); err != nil {
		return err
	}
	if p.Silenced {
		return nil
	}
	return enqueue(ctx, tx, p, DedupKey(p.AlertID, p.Kind))
}

// EnqueueEvent registra e enfileira uma notificação que não vem de um alerta (ex.: IP banido).
// dedupKey impede mensagens repetidas por canal.
func EnqueueEvent(ctx context.Context, tx pgx.Tx, p Payload, dedupKey string) error {
	if err := Record(ctx, tx, p); err != nil {
		return err
	}
	return enqueue(ctx, tx, p, dedupKey)
}

func enqueue(ctx context.Context, tx pgx.Tx, p Payload, dedupKey string) error {
	rows, err := tx.Query(ctx, `SELECT id, COALESCE(config->>'min_severity', 'info')
		FROM notification_channels WHERE is_enabled AND channel_type = 'telegram'`)
	if err != nil {
		return err
	}
	type ch struct{ id, min string }
	var chans []ch
	for rows.Next() {
		var c ch
		if err := rows.Scan(&c.id, &c.min); err != nil {
			rows.Close()
			return err
		}
		chans = append(chans, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	for _, c := range chans {
		if Rank(p.Severity) < Rank(c.min) {
			continue
		}
		if p.Kind == KindResolved {
			var sent bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notification_outbox WHERE channel_id = $1 AND dedup_key = $2)`,
				c.id, DedupKey(p.AlertID, KindTriggered)).Scan(&sent); err != nil {
				return err
			}
			if !sent {
				continue
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_outbox (channel_id, dedup_key, payload)
			VALUES ($1, $2, $3) ON CONFLICT (channel_id, dedup_key) DO NOTHING`,
			c.id, dedupKey, raw); err != nil {
			return err
		}
	}
	return nil
}
