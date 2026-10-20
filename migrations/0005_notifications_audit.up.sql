CREATE TABLE notification_channels (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    channel_type     text        NOT NULL CHECK (channel_type IN ('telegram')),
    config           jsonb       NOT NULL DEFAULT '{}'::jsonb, -- dados não secretos (ex.: chat_id autorizado)
    secret_encrypted bytea,                                    -- token cifrado (AES-GCM, chave fora do banco)
    is_enabled       boolean     NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Fila persistente (outbox): sobrevive a reinícios; dedup_key evita mensagens repetidas.
CREATE TABLE notification_outbox (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id      uuid        NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    dedup_key       text        NOT NULL,
    payload         jsonb       NOT NULL,
    status          text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE UNIQUE INDEX notification_outbox_dedup_key ON notification_outbox (channel_id, dedup_key);
CREATE INDEX notification_outbox_due_idx ON notification_outbox (next_attempt_at) WHERE status = 'pending';

CREATE TABLE audit_logs (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id uuid        REFERENCES users (id) ON DELETE SET NULL,
    action        text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text,
    metadata      jsonb       NOT NULL DEFAULT '{}'::jsonb, -- nunca conter senhas/tokens
    ip            inet,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_created_idx ON audit_logs (created_at DESC);
CREATE INDEX audit_logs_resource_idx ON audit_logs (resource_type, resource_id);
