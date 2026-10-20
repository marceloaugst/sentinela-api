package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/secrets"
	"sentinela/internal/services"
	"sentinela/internal/telemetry"
)

// Worker entrega as notificações pendentes da fila. A reserva (lease) é feita avançando
// next_attempt_at dentro da transação de seleção (FOR UPDATE SKIP LOCKED): várias instâncias
// não enviam a mesma mensagem e, se o processo cair no meio do envio, ela volta à fila ao fim do lease.
type Worker struct {
	Pool        *pgxpool.Pool
	Box         *secrets.Box
	Sender      Sender
	Channels    *ChannelRepository // para checar destinos autorizados no envio
	Log         *slog.Logger
	Metrics     *telemetry.Metrics
	MaxAttempts int
	Batch       int
	Lease       time.Duration
	Backoff     func(attempt int) time.Duration
	Now         func() time.Time
}

// DefaultBackoff: 30 s, 1 min, 2 min, 4 min... limitado a 30 min, com ±20% de variação.
func DefaultBackoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < 30*time.Minute; i++ {
		d *= 2
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

type job struct {
	id        int64
	channelID string
	payload   Payload
	attempts  int
}

func (w *Worker) count(result string) {
	if w.Metrics != nil {
		w.Metrics.Notifications.WithLabelValues(result).Inc()
	}
}

func (w *Worker) claim(ctx context.Context) ([]job, error) {
	batch, lease := w.Batch, w.Lease
	if batch <= 0 {
		batch = 20
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := tx.Query(ctx, `SELECT id, channel_id, payload, attempts FROM notification_outbox
		WHERE status = 'pending' AND next_attempt_at <= now()
		ORDER BY next_attempt_at, id LIMIT $1 FOR UPDATE SKIP LOCKED`, batch)
	if err != nil {
		return nil, err
	}
	var jobs []job
	for rows.Next() {
		var j job
		var raw []byte
		if err := rows.Scan(&j.id, &j.channelID, &raw, &j.attempts); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &j.payload); err != nil {
			rows.Close()
			return nil, err
		}
		j.attempts++
		jobs = append(jobs, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, j := range jobs {
		if _, err := tx.Exec(ctx, `UPDATE notification_outbox SET attempts = $2, next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1`,
			j.id, j.attempts, lease.Seconds()); err != nil {
			return nil, err
		}
	}
	return jobs, tx.Commit(ctx)
}

// Tick entrega o que estiver vencido.
func (w *Worker) Tick(ctx context.Context) error {
	jobs, err := w.claim(ctx)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			return ctx.Err() // o restante volta à fila quando o lease expirar
		}
		w.deliver(ctx, j)
	}
	return nil
}

func (w *Worker) finish(ctx context.Context, j job, status, errMsg string, retryIn time.Duration) {
	var err error
	switch status {
	case "sent":
		_, err = w.Pool.Exec(ctx, `UPDATE notification_outbox SET status = 'sent', sent_at = now(), last_error = NULL WHERE id = $1`, j.id)
	case "failed":
		_, err = w.Pool.Exec(ctx, `UPDATE notification_outbox SET status = 'failed', last_error = $2 WHERE id = $1`, j.id, services.SanitizeError(errMsg))
	default: // retry
		_, err = w.Pool.Exec(ctx, `UPDATE notification_outbox SET last_error = $2, next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1`,
			j.id, services.SanitizeError(errMsg), retryIn.Seconds())
	}
	if err != nil {
		w.Log.Error("falha ao atualizar a fila de notificações", "id", j.id, "err", err)
	}
}

func (w *Worker) deliver(ctx context.Context, j job) {
	var enabled bool
	var chat string
	var enc []byte
	err := w.Pool.QueryRow(ctx, `SELECT is_enabled, COALESCE(config->>'chat_id',''), secret_encrypted
		FROM notification_channels WHERE id = $1`, j.channelID).Scan(&enabled, &chat, &enc)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		w.fail(ctx, j, "canal removido ou desabilitado")
		return
	}
	if err != nil {
		w.Log.Error("falha ao ler canal", "channel_id", j.channelID, "err", err)
		w.finish(ctx, j, "retry", "erro interno ao ler o canal", DefaultBackoff(j.attempts))
		return
	}
	// defesa em profundidade: o destino precisa estar autorizado também no momento do envio
	if w.Channels != nil && !w.Channels.ChatAllowed(chat) {
		w.fail(ctx, j, "chat_id não autorizado")
		return
	}
	if w.Box == nil || enc == nil {
		w.fail(ctx, j, "token do canal indisponível (SECRETS_KEY ausente ou canal sem token)")
		return
	}
	token, err := w.Box.Decrypt(enc)
	if err != nil {
		w.fail(ctx, j, "não foi possível decifrar o token do canal")
		return
	}

	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = w.Sender.Send(sctx, string(token), chat, FormatText(j.payload))
	if err == nil {
		w.count("sent")
		w.finish(ctx, j, "sent", "", 0)
		return
	}
	var se *SendError
	if !errors.As(err, &se) {
		se = &SendError{Reason: "erro desconhecido no envio"}
	}
	max := w.MaxAttempts
	if max <= 0 {
		max = 8
	}
	if se.Permanent || j.attempts >= max {
		w.Log.Warn("notificação não entregue", "id", j.id, "attempts", j.attempts, "reason", se.Reason)
		w.fail(ctx, j, se.Reason)
		return
	}
	backoff := w.Backoff
	if backoff == nil {
		backoff = DefaultBackoff
	}
	delay := backoff(j.attempts)
	if se.RetryAfter > delay {
		delay = se.RetryAfter
	}
	w.count("retry")
	w.Log.Warn("falha ao enviar notificação; nova tentativa agendada", "id", j.id, "attempt", j.attempts, "in", delay.String(), "reason", se.Reason)
	w.finish(ctx, j, "retry", se.Reason, delay)
}

func (w *Worker) fail(ctx context.Context, j job, reason string) {
	w.count("failed")
	w.finish(ctx, j, "failed", reason, 0)
}
