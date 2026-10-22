package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/audit"
	"sentinela/internal/secrets"
	"sentinela/internal/validation"
)

var (
	ErrChannelNotFound = errors.New("canal não encontrado")
	ErrNoSecretsKey    = secrets.ErrNoKey
	ErrChatNotAllowed  = errors.New("chat_id não está na lista de destinos autorizados")
)

const EnvChannelName = "Telegram (ambiente)"

// Channel nunca expõe o token: apenas se há um configurado.
type Channel struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"channel_type"`
	ChatID      string    `json:"chat_id"`
	MinSeverity string    `json:"min_severity"`
	IsEnabled   bool      `json:"is_enabled"`
	HasToken    bool      `json:"has_token"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateInput struct {
	Name        string `json:"name"`
	Type        string `json:"channel_type"`
	BotToken    string `json:"bot_token"`
	ChatID      string `json:"chat_id"`
	MinSeverity string `json:"min_severity"`
	IsEnabled   *bool  `json:"is_enabled"`
}

type UpdateInput struct {
	Name        *string `json:"name"`
	BotToken    *string `json:"bot_token"`
	ChatID      *string `json:"chat_id"`
	MinSeverity *string `json:"min_severity"`
	IsEnabled   *bool   `json:"is_enabled"`
}

var (
	tokenRe  = regexp.MustCompile(`^\d{5,15}:[A-Za-z0-9_-]{30,64}$`)
	chatIDRe = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

func validToken(t string) bool  { return tokenRe.MatchString(t) }
func validChatID(c string) bool { return chatIDRe.MatchString(c) }

func validSeverity(s string) bool { return Rank(s) > 0 }

func (in *CreateInput) Validate() validation.Problems {
	var p validation.Problems
	in.Name = p.Text("name", in.Name, 1, 120)
	if in.Type == "" {
		in.Type = "telegram"
	}
	if in.Type != "telegram" {
		p.Add("channel_type", "somente telegram é suportado")
	}
	in.BotToken = strings.TrimSpace(in.BotToken)
	if !validToken(in.BotToken) {
		p.Add("bot_token", "formato inválido (esperado 123456:ABC...)")
	}
	in.ChatID = strings.TrimSpace(in.ChatID)
	if !validChatID(in.ChatID) {
		p.Add("chat_id", "deve ser um número (ex.: -1001234567890) ou @canal")
	}
	if in.MinSeverity == "" {
		in.MinSeverity = "info"
	}
	if !validSeverity(in.MinSeverity) {
		p.Add("min_severity", "deve ser info, warning ou critical")
	}
	return p
}

func (in *UpdateInput) Validate() validation.Problems {
	var p validation.Problems
	if *in == (UpdateInput{}) {
		p.Add("body", "informe ao menos um campo")
		return p
	}
	if in.Name != nil {
		n := p.Text("name", *in.Name, 1, 120)
		in.Name = &n
	}
	if in.BotToken != nil {
		t := strings.TrimSpace(*in.BotToken)
		in.BotToken = &t
		if !validToken(t) {
			p.Add("bot_token", "formato inválido (esperado 123456:ABC...)")
		}
	}
	if in.ChatID != nil {
		c := strings.TrimSpace(*in.ChatID)
		in.ChatID = &c
		if !validChatID(c) {
			p.Add("chat_id", "deve ser um número (ex.: -1001234567890) ou @canal")
		}
	}
	if in.MinSeverity != nil && !validSeverity(*in.MinSeverity) {
		p.Add("min_severity", "deve ser info, warning ou critical")
	}
	return p
}

type ChannelRepository struct {
	pool    *pgxpool.Pool
	box     *secrets.Box        // nil = SECRETS_KEY ausente
	allowed map[string]struct{} // destinos autorizados
}

func NewChannelRepository(pool *pgxpool.Pool, box *secrets.Box, allowedChats []string) *ChannelRepository {
	m := make(map[string]struct{}, len(allowedChats))
	for _, c := range allowedChats {
		if c = strings.TrimSpace(c); c != "" {
			m[c] = struct{}{}
		}
	}
	return &ChannelRepository{pool: pool, box: box, allowed: m}
}

// ChatAllowed informa se o destino está autorizado. Sem nenhum destino configurado, nada é autorizado.
func (r *ChannelRepository) ChatAllowed(chat string) bool { _, ok := r.allowed[chat]; return ok }

const chCols = `id, name, channel_type, COALESCE(config->>'chat_id', ''), COALESCE(config->>'min_severity', 'info'),
	is_enabled, secret_encrypted IS NOT NULL, created_at, updated_at`

func scanChannel(row pgx.Row) (Channel, error) {
	var c Channel
	err := row.Scan(&c.ID, &c.Name, &c.Type, &c.ChatID, &c.MinSeverity, &c.IsEnabled, &c.HasToken, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func cfgJSON(chat, min string) []byte {
	b, _ := json.Marshal(map[string]string{"chat_id": chat, "min_severity": min})
	return b
}

func (r *ChannelRepository) Create(ctx context.Context, ac audit.Context, in CreateInput) (Channel, error) {
	if r.box == nil {
		return Channel{}, ErrNoSecretsKey
	}
	if !r.ChatAllowed(in.ChatID) {
		return Channel{}, ErrChatNotAllowed
	}
	enc, err := r.box.Encrypt([]byte(in.BotToken))
	if err != nil {
		return Channel{}, err
	}
	enabled := true
	if in.IsEnabled != nil {
		enabled = *in.IsEnabled
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Channel{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	c, err := scanChannel(tx.QueryRow(ctx, `INSERT INTO notification_channels (name, channel_type, config, secret_encrypted, is_enabled)
		VALUES ($1,$2,$3,$4,$5) RETURNING `+chCols, in.Name, in.Type, cfgJSON(in.ChatID, in.MinSeverity), enc, enabled))
	if err != nil {
		return Channel{}, err
	}
	// o token jamais vai para a auditoria
	if err := audit.Write(ctx, tx, ac, "notification_channel.create", "notification_channel", c.ID,
		map[string]any{"name": c.Name, "type": c.Type, "chat_id": c.ChatID, "min_severity": c.MinSeverity}); err != nil {
		return Channel{}, err
	}
	return c, tx.Commit(ctx)
}

func (r *ChannelRepository) Get(ctx context.Context, id string) (Channel, error) {
	c, err := scanChannel(r.pool.QueryRow(ctx, `SELECT `+chCols+` FROM notification_channels WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Channel{}, ErrChannelNotFound
	}
	return c, err
}

func (r *ChannelRepository) List(ctx context.Context) ([]Channel, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+chCols+` FROM notification_channels ORDER BY lower(name), id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *ChannelRepository) Update(ctx context.Context, ac audit.Context, id string, in UpdateInput) (Channel, error) {
	cur, err := r.Get(ctx, id)
	if err != nil {
		return Channel{}, err
	}
	chat, min := cur.ChatID, cur.MinSeverity
	if in.ChatID != nil {
		chat = *in.ChatID
	}
	if in.MinSeverity != nil {
		min = *in.MinSeverity
	}
	if in.ChatID != nil && !r.ChatAllowed(chat) {
		return Channel{}, ErrChatNotAllowed
	}
	var enc []byte
	if in.BotToken != nil {
		if r.box == nil {
			return Channel{}, ErrNoSecretsKey
		}
		if enc, err = r.box.Encrypt([]byte(*in.BotToken)); err != nil {
			return Channel{}, err
		}
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Channel{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	c, err := scanChannel(tx.QueryRow(ctx, `UPDATE notification_channels SET
			name = COALESCE($2, name), config = $3, secret_encrypted = COALESCE($4, secret_encrypted),
			is_enabled = COALESCE($5, is_enabled), updated_at = now()
		WHERE id = $1 RETURNING `+chCols, id, in.Name, cfgJSON(chat, min), enc, in.IsEnabled))
	if errors.Is(err, pgx.ErrNoRows) {
		return Channel{}, ErrChannelNotFound
	}
	if err != nil {
		return Channel{}, err
	}
	meta := map[string]any{"chat_id": c.ChatID, "min_severity": c.MinSeverity, "enabled": c.IsEnabled, "token_changed": in.BotToken != nil}
	if err := audit.Write(ctx, tx, ac, "notification_channel.update", "notification_channel", id, meta); err != nil {
		return Channel{}, err
	}
	return c, tx.Commit(ctx)
}

func (r *ChannelRepository) Delete(ctx context.Context, ac audit.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrChannelNotFound
	}
	if err := audit.Write(ctx, tx, ac, "notification_channel.delete", "notification_channel", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EnqueueTest enfileira uma mensagem de teste (chave única, então cada teste é enviado).
func (r *ChannelRepository) EnqueueTest(ctx context.Context, id string) error {
	if _, err := r.Get(ctx, id); err != nil {
		return err
	}
	raw, _ := json.Marshal(Payload{Kind: KindTest, At: time.Now().UTC()})
	_, err := r.pool.Exec(ctx, `INSERT INTO notification_outbox (channel_id, dedup_key, payload)
		VALUES ($1, 'test:' || gen_random_uuid()::text, $2)`, id, raw)
	return err
}

// UpsertFromEnv cria/atualiza o canal "Telegram (ambiente)" a partir de TELEGRAM_BOT_TOKEN e
// TELEGRAM_CHAT_ID, gravando o token cifrado. Idempotente: seguro a cada inicialização.
func (r *ChannelRepository) UpsertFromEnv(ctx context.Context, token, chat string) error {
	if token == "" || chat == "" {
		return nil
	}
	if r.box == nil {
		return ErrNoSecretsKey
	}
	if !validToken(token) || !validChatID(chat) {
		return errors.New("TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID com formato inválido")
	}
	enc, err := r.box.Encrypt([]byte(token))
	if err != nil {
		return err
	}
	tag, err := r.pool.Exec(ctx, `UPDATE notification_channels SET
			config = jsonb_set(config, '{chat_id}', to_jsonb($2::text)), secret_encrypted = $3, updated_at = now()
		WHERE name = $1 AND channel_type = 'telegram'`, EnvChannelName, chat, enc)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO notification_channels (name, channel_type, config, secret_encrypted)
		VALUES ($1, 'telegram', $2, $3)`, EnvChannelName, cfgJSON(chat, "critical"), enc)
	return err
}
