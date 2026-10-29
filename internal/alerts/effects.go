package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"sentinela/internal/events"
	"sentinela/internal/notifications"
	"sentinela/internal/procs"
	"sentinela/internal/silences"
)

// alertRow é o estado persistido de um alerta ativo.
type alertRow struct {
	ID              string
	RuleID          string
	ServerID        string
	ServiceID       *string
	IncidentID      *string
	Status          string
	Severity        string
	Message         string
	PendingSince    *time.Time
	RecoveringSince *time.Time
	Silenced        bool
}

func (a alertRow) state() State {
	return State{Exists: true, Status: a.Status, PendingSince: a.PendingSince, RecoveringSince: a.RecoveringSince}
}

// Target é um alvo avaliado por uma regra: um servidor, ou um serviço de um servidor.
type Target struct {
	ServerID    string
	ServerName  string
	ServiceID   *string
	ServiceName string
	Value       float64
	HasValue    bool // false = sem dados confiáveis agora (não avalia nem resolve)
	Detail      string
	// Culprits são os maiores consumidores de CPU/memória, preenchidos só na hora de disparar (veja Evaluator.culprits).
	Culprits *procs.Culprits
}

func (t Target) key() string {
	if t.ServiceID != nil {
		return t.ServerID + "|" + *t.ServiceID
	}
	return t.ServerID + "|"
}

func (a alertRow) key() string {
	if a.ServiceID != nil {
		return a.ServerID + "|" + *a.ServiceID
	}
	return a.ServerID + "|"
}

func addEvent(ctx context.Context, tx pgx.Tx, incidentID, typ, msg string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO incident_events (incident_id, event_type, message, created_at) VALUES ($1,$2,$3,$4)`,
		incidentID, typ, msg, now)
	return err
}

// recurrenceWindow: incidentes iguais dentro dessa janela contam como reincidência.
const recurrenceWindow = 24 * time.Hour

// findOrCreateIncident garante no máximo um incidente ABERTO por (servidor, regra, serviço):
// uma falha contínua reutiliza o mesmo incidente em vez de criar vários. Ao abrir um novo, conta
// quantos incidentes iguais foram resolvidos nas últimas 24 h (reincidência).
func findOrCreateIncident(ctx context.Context, tx pgx.Tx, rule Rule, t Target, now time.Time) (id string, recurrence int, created bool, err error) {
	var cur int
	err = tx.QueryRow(ctx, `SELECT id, recurrence_count FROM incidents WHERE status = 'open' AND server_id = $1 AND rule_id = $2
		AND service_id IS NOT DISTINCT FROM $3::uuid`, t.ServerID, rule.ID, t.ServiceID).Scan(&id, &cur)
	if err == nil {
		return id, cur, false, nil
	}
	if err != pgx.ErrNoRows {
		return "", 0, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE status = 'resolved' AND server_id = $1 AND rule_id = $2
		AND service_id IS NOT DISTINCT FROM $3::uuid AND resolved_at >= $4`,
		t.ServerID, rule.ID, t.ServiceID, now.Add(-recurrenceWindow)).Scan(&recurrence); err != nil {
		return "", 0, false, err
	}
	title := incidentTitle(rule, t)
	if err := tx.QueryRow(ctx, `INSERT INTO incidents (server_id, rule_id, service_id, title, severity, priority, recurrence_count, started_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, t.ServerID, rule.ID, t.ServiceID, title, rule.Severity, priorityOf(rule), recurrence, now).Scan(&id); err != nil {
		return "", 0, false, err
	}
	if err := addEvent(ctx, tx, id, "opened", fmt.Sprintf("Incidente aberto (P%d): %s", priorityOf(rule), title), now); err != nil {
		return "", 0, false, err
	}
	if recurrence > 0 {
		if err := addEvent(ctx, tx, id, "recurrent", fmt.Sprintf("Reincidente: %d incidente(s) igual(is) resolvido(s) nas últimas 24 h", recurrence), now); err != nil {
			return "", 0, false, err
		}
	}
	return id, recurrence, true, nil
}

func incidentTitle(rule Rule, t Target) string {
	title := rule.Name + " — " + t.ServerName
	if t.ServiceName != "" {
		title += " / " + t.ServiceName
	}
	return title
}

// priorityOf: regras sem prioridade (anteriores ao catálogo) valem P3.
func priorityOf(r Rule) int {
	if r.Priority < P1 || r.Priority > P4 {
		return P3
	}
	return r.Priority
}

// ---- eventos em tempo real (sem segredos, alvos nem hostnames) ----

type alertEvent struct {
	AlertID     string    `json:"alert_id"`
	IncidentID  string    `json:"incident_id,omitempty"`
	ServerID    string    `json:"server_id"`
	ServerName  string    `json:"server_name"`
	ServiceID   *string   `json:"service_id,omitempty"`
	ServiceName string    `json:"service_name,omitempty"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Message     string    `json:"message"`
	At          time.Time `json:"at"`
}

type incidentEvent struct {
	IncidentID  string     `json:"incident_id"`
	ServerID    string     `json:"server_id"`
	ServerName  string     `json:"server_name"`
	ServiceID   *string    `json:"service_id,omitempty"`
	ServiceName string     `json:"service_name,omitempty"`
	RuleID      string     `json:"rule_id"`
	RuleName    string     `json:"rule_name"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Priority    int        `json:"priority"`
	Recurrence  int        `json:"recurrence_count"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// fire cria (ou promove de pending) o alerta, abre/reutiliza o incidente e enfileira a notificação,
// tudo na transação do avaliador.
func fire(ctx context.Context, tx pgx.Tx, rule Rule, t Target, existing *alertRow, now time.Time) error {
	msg := Message(rule, t.Value, t.Detail)
	var culprits []byte // jsonb; nulo quando não há consumidores a apontar
	if c := t.Culprits; c != nil {
		if txt := c.Text(); txt != "" {
			msg += ". " + txt
			if b, err := json.Marshal(c); err == nil {
				culprits = b
			}
		}
	}
	silence, err := silences.ActiveFor(ctx, tx, t.ServerID, rule.ID, now)
	if err != nil {
		return err
	}
	var alertID string
	if existing != nil {
		alertID = existing.ID
		if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'firing', triggered_at = $2, pending_since = NULL,
				recovering_since = NULL, value = $3, message = $4, severity = $5, last_evaluated_at = $2, culprits = $6, silenced = $7 WHERE id = $1`,
			alertID, now, t.Value, msg, rule.Severity, culprits, silence != nil); err != nil {
			return err
		}
	} else if err := tx.QueryRow(ctx, `INSERT INTO alerts (rule_id, server_id, service_id, status, severity, message, value, triggered_at, last_evaluated_at, culprits, silenced)
		VALUES ($1,$2,$3,'firing',$4,$5,$6,$7,$7,$8,$9) RETURNING id`,
		rule.ID, t.ServerID, t.ServiceID, rule.Severity, msg, t.Value, now, culprits, silence != nil).Scan(&alertID); err != nil {
		return err
	}
	incID, recurrence, createdIncident, err := findOrCreateIncident(ctx, tx, rule, t, now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts SET incident_id = $2 WHERE id = $1`, alertID, incID); err != nil {
		return err
	}
	if err := addEvent(ctx, tx, incID, "alert_triggered", msg, now); err != nil {
		return err
	}
	pl := notifications.Payload{
		Kind: notifications.KindTriggered, ServerID: t.ServerID, AlertID: alertID, IncidentID: incID,
		ServerName: t.ServerName, ServiceName: t.ServiceName, RuleName: rule.Name,
		Severity: rule.Severity, Priority: priorityOf(rule), Recurrence: recurrence, Message: msg, At: now,
	}
	if silence != nil {
		pl.Silenced, pl.SilenceReason = true, silence.Reason
		if err := addEvent(ctx, tx, incID, "silenced", "Notificação silenciada: "+silence.Reason, now); err != nil {
			return err
		}
	}
	if err := notifications.EnqueueAlert(ctx, tx, pl); err != nil {
		return err
	}
	// Eventos por ÚLTIMO (ver events.Publish): incidente primeiro, depois o alerta.
	if createdIncident {
		title := incidentTitle(rule, t)
		if err := events.Publish(ctx, tx, events.TypeIncidentCreated, t.ServerID, incidentEvent{
			IncidentID: incID, ServerID: t.ServerID, ServerName: t.ServerName, ServiceID: t.ServiceID, ServiceName: t.ServiceName,
			RuleID: rule.ID, RuleName: rule.Name, Title: title, Severity: rule.Severity, Priority: priorityOf(rule), Recurrence: recurrence, Status: "open", StartedAt: now,
		}); err != nil {
			return err
		}
	}
	return events.Publish(ctx, tx, events.TypeAlertTriggered, t.ServerID, alertEvent{
		AlertID: alertID, IncidentID: incID, ServerID: t.ServerID, ServerName: t.ServerName, ServiceID: t.ServiceID,
		ServiceName: t.ServiceName, RuleID: rule.ID, RuleName: rule.Name, Severity: rule.Severity,
		Status: StatusFiring, Message: msg, At: now,
	})
}

// releaseSilenced envia a notificação de um alerta que disparou durante um silenciamento, assim que nenhuma janela o cobre mais
// e ele continua aberto. Reconhecido (alguém já sabe) só limpa a marca. Chamado a cada avaliação de alertas marcados.
func releaseSilenced(ctx context.Context, tx pgx.Tx, rule Rule, t Target, a alertRow, now time.Time) error {
	s, err := silences.ActiveFor(ctx, tx, a.ServerID, a.RuleID, now)
	if err != nil || s != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts SET silenced = false WHERE id = $1`, a.ID); err != nil {
		return err
	}
	if a.Status != StatusFiring || a.IncidentID == nil {
		return nil
	}
	if err := addEvent(ctx, tx, *a.IncidentID, "silence_ended", "Silenciamento encerrado com o alerta ainda aberto; notificação enviada", now); err != nil {
		return err
	}
	return notifications.EnqueueAlert(ctx, tx, notifications.Payload{
		Kind: notifications.KindTriggered, ServerID: a.ServerID, AlertID: a.ID, IncidentID: *a.IncidentID,
		ServerName: t.ServerName, ServiceName: t.ServiceName, RuleName: rule.Name,
		Severity: a.Severity, Priority: priorityOf(rule), Message: a.Message + " (silenciamento encerrado; o problema continua)", At: now,
	})
}

// ResolveReason descreve por que um alerta foi resolvido (gravado em alerts.resolved_reason).
const (
	ReasonRecovered    = "recovered" // condição deixou de existir
	ReasonManual       = "manual"    // operador resolveu
	ReasonRuleDisabled = "rule_disabled"
	ReasonRuleDeleted  = "rule_deleted"
	ReasonOutOfScope   = "out_of_scope" // servidor/serviço removido, desativado ou em manutenção
)

// resolve fecha o alerta e o incidente associado, enfileira o aviso de recuperação e publica os eventos.
func resolve(ctx context.Context, tx pgx.Tx, a alertRow, reason, actor string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $2, resolved_reason = $3,
			recovering_since = NULL, pending_since = NULL, last_evaluated_at = $2 WHERE id = $1`, a.ID, now, reason); err != nil {
		return err
	}
	label := map[string]string{
		ReasonRecovered:    "Condição normalizada",
		ReasonManual:       "Resolvido manualmente por " + actor,
		ReasonRuleDisabled: "Regra desativada",
		ReasonRuleDeleted:  "Regra removida",
		ReasonOutOfScope:   "Servidor/serviço removido, desativado ou em manutenção",
	}[reason]

	incidentClosed := false
	if a.IncidentID != nil {
		if err := addEvent(ctx, tx, *a.IncidentID, "alert_resolved", label, now); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE incidents SET status = 'resolved', resolved_at = $2 WHERE id = $1 AND status = 'open'`, *a.IncidentID, now)
		if err != nil {
			return err
		}
		if incidentClosed = tag.RowsAffected() == 1; incidentClosed {
			if err := addEvent(ctx, tx, *a.IncidentID, "resolved", "Incidente resolvido", now); err != nil {
				return err
			}
		}
	}

	var serverName, ruleName string
	var serviceName *string
	if err := tx.QueryRow(ctx, `SELECT s.name, r.name, ms.name FROM alerts a
		JOIN servers s ON s.id = a.server_id JOIN alert_rules r ON r.id = a.rule_id
		LEFT JOIN monitored_services ms ON ms.id = a.service_id WHERE a.id = $1`, a.ID).Scan(&serverName, &ruleName, &serviceName); err != nil {
		return err
	}
	svc := ""
	if serviceName != nil {
		svc = *serviceName
	}
	incID := ""
	if a.IncidentID != nil {
		incID = *a.IncidentID
		if err := notifications.EnqueueAlert(ctx, tx, notifications.Payload{
			Kind: notifications.KindResolved, ServerID: a.ServerID, AlertID: a.ID, IncidentID: incID, ServerName: serverName, ServiceName: svc,
			RuleName: ruleName, Severity: a.Severity, Message: fmt.Sprintf("Condição normalizada. Alerta original: %s", a.Message), At: now,
		}); err != nil {
			return err
		}
	}

	// Eventos por ÚLTIMO (ver events.Publish).
	if err := events.Publish(ctx, tx, events.TypeAlertResolved, a.ServerID, alertEvent{
		AlertID: a.ID, IncidentID: incID, ServerID: a.ServerID, ServerName: serverName, ServiceID: a.ServiceID, ServiceName: svc,
		RuleID: a.RuleID, RuleName: ruleName, Severity: a.Severity, Status: StatusResolved, Message: a.Message, At: now,
	}); err != nil {
		return err
	}
	if !incidentClosed {
		return nil
	}
	var title, sev string
	var prio, recurrence int
	var started time.Time
	if err := tx.QueryRow(ctx, `SELECT title, severity, priority, recurrence_count, started_at FROM incidents WHERE id = $1`, incID).Scan(&title, &sev, &prio, &recurrence, &started); err != nil {
		return err
	}
	return events.Publish(ctx, tx, events.TypeIncidentResolved, a.ServerID, incidentEvent{
		IncidentID: incID, ServerID: a.ServerID, ServerName: serverName, ServiceID: a.ServiceID, ServiceName: svc,
		RuleID: a.RuleID, RuleName: ruleName, Title: title, Severity: sev, Priority: prio, Recurrence: recurrence, Status: "resolved", StartedAt: started, ResolvedAt: &now,
	})
}
