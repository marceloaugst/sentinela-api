-- Silenciamentos e janelas de manutenção. Enquanto ativo (starts_at <= agora < ends_at e não cancelado), os alertas que
-- casam com o escopo continuam sendo avaliados e registrados, mas NÃO geram notificação externa (Telegram).
-- server_id e rule_id nulos = "todos".
CREATE TABLE alert_silences (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         text        NOT NULL CHECK (kind IN ('silence', 'maintenance')),
    reason       text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 300),
    server_id    uuid        REFERENCES servers (id) ON DELETE CASCADE,
    rule_id      uuid        REFERENCES alert_rules (id) ON DELETE CASCADE,
    starts_at    timestamptz NOT NULL,
    ends_at      timestamptz NOT NULL,
    created_by   uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_by_label text    NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    cancelled_at timestamptz,
    cancelled_by_label text,
    CHECK (ends_at > starts_at)
);
CREATE INDEX alert_silences_window_idx ON alert_silences (ends_at, starts_at) WHERE cancelled_at IS NULL;

-- true = o disparo foi silenciado e nenhuma notificação externa saiu ainda; o avaliador a envia quando a janela termina
-- (se o alerta continuar aberto), para um problema persistente não ficar invisível.
ALTER TABLE alerts ADD COLUMN silenced boolean NOT NULL DEFAULT false;
