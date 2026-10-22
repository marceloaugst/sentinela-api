-- Métricas de sistema (ClickHouse) entram no catálogo de alertas.
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_name_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_name_check CHECK (metric_name IN
    ('cpu_usage_percent', 'memory_used_percent', 'disk_used_percent', 'load_average_1m',
     'server_offline', 'service_down', 'swap_used_percent', 'load_per_cpu',
     'oom_kills_10m', 'inode_used_percent', 'disk_latency_ms', 'ntp_unsynchronized',
     'security_updates', 'cert_days_left'));

-- Registro permanente de TODA notificação gerada (alertas disparados e recuperados, IPs banidos...),
-- independente de haver canal externo (Telegram) configurado ou de a entrega ter funcionado.
CREATE TABLE notifications (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text        NOT NULL CHECK (kind IN ('alert_triggered', 'alert_resolved', 'ip_banned')),
    priority    smallint    NOT NULL CHECK (priority BETWEEN 1 AND 4),
    severity    text        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    -- Sem chaves estrangeiras de propósito: é um registro histórico (o nome do servidor, do alerta etc. também
    -- vai em "data") que nunca pode falhar nem sumir junto com o objeto de origem.
    server_id   uuid,
    alert_id    uuid,
    incident_id uuid,
    title       text        NOT NULL,
    message     text        NOT NULL,
    data        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    read_at     timestamptz,
    read_by     uuid        REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX notifications_created_idx ON notifications (created_at DESC, id DESC);
CREATE INDEX notifications_unread_idx ON notifications (created_at DESC) WHERE read_at IS NULL;
CREATE INDEX notifications_server_idx ON notifications (server_id, created_at DESC);
-- Um aviso por alerta/tipo (e por ban): reprocessar não duplica o registro.
CREATE UNIQUE INDEX notifications_dedup_key ON notifications (kind, alert_id) WHERE alert_id IS NOT NULL;

-- Todo tipo de alerta vira mensagem no Telegram: canais existentes passam a receber desde "info".
UPDATE notification_channels SET config = jsonb_set(config, '{min_severity}', '"info"') WHERE channel_type = 'telegram';
