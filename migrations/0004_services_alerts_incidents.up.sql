CREATE TABLE monitored_services (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       uuid        REFERENCES servers (id),
    name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    service_type    text        NOT NULL CHECK (service_type IN ('http', 'systemd', 'tcp')),
    target          text        NOT NULL,
    config          jsonb       NOT NULL DEFAULT '{}'::jsonb, -- timeout, intervalo, critérios de sucesso
    status          text        NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'up', 'down', 'degraded')),
    last_checked_at timestamptz,
    deleted_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX monitored_services_server_idx ON monitored_services (server_id) WHERE deleted_at IS NULL;

CREATE TABLE alert_rules (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text             NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    metric_name      text             NOT NULL CHECK (metric_name IN
        ('cpu_usage_percent', 'memory_used_percent', 'disk_used_percent', 'load_average_1m',
         'server_offline', 'service_down')),
    operator         text             NOT NULL CHECK (operator IN ('>', '>=', '<', '<=', '==')),
    threshold        double precision NOT NULL,
    severity         text             NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    duration_seconds integer          NOT NULL DEFAULT 0 CHECK (duration_seconds >= 0),
    recovery_seconds integer          NOT NULL DEFAULT 0 CHECK (recovery_seconds >= 0),
    server_id        uuid             REFERENCES servers (id), -- NULL = regra global
    is_enabled       boolean          NOT NULL DEFAULT true,
    created_at       timestamptz      NOT NULL DEFAULT now(),
    updated_at       timestamptz      NOT NULL DEFAULT now()
);
CREATE INDEX alert_rules_enabled_idx ON alert_rules (is_enabled);

CREATE TABLE incidents (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   uuid        REFERENCES servers (id),
    rule_id     uuid        REFERENCES alert_rules (id) ON DELETE SET NULL,
    service_id  uuid        REFERENCES monitored_services (id) ON DELETE SET NULL,
    title       text        NOT NULL,
    severity    text        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    status      text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    started_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);
-- Um único incidente aberto por (servidor, regra, serviço): falha contínua não duplica incidentes.
CREATE UNIQUE INDEX incidents_open_key ON incidents (
    COALESCE(server_id, '00000000-0000-0000-0000-000000000000'::uuid),
    COALESCE(rule_id, '00000000-0000-0000-0000-000000000000'::uuid),
    COALESCE(service_id, '00000000-0000-0000-0000-000000000000'::uuid)
) WHERE status = 'open';
CREATE INDEX incidents_server_started_idx ON incidents (server_id, started_at DESC);
CREATE INDEX incidents_started_idx ON incidents (started_at DESC);

CREATE TABLE incident_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id uuid        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event_type  text        NOT NULL, -- opened, alert_triggered, acknowledged, notified, resolved...
    message     text        NOT NULL DEFAULT '',
    actor_id    uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_events_incident_idx ON incident_events (incident_id, created_at);

-- Alerta = ocorrência de uma condição de regra; incidente = agrupamento da falha contínua;
-- reconhecimento = ação de um usuário sobre o alerta.
CREATE TABLE alerts (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id           uuid        NOT NULL REFERENCES alert_rules (id),
    server_id         uuid        NOT NULL REFERENCES servers (id),
    service_id        uuid        REFERENCES monitored_services (id),
    incident_id       uuid        REFERENCES incidents (id),
    status            text        NOT NULL DEFAULT 'firing' CHECK (status IN ('pending', 'firing', 'acknowledged', 'resolved')),
    severity          text        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    message           text        NOT NULL,
    value             double precision,
    triggered_at      timestamptz NOT NULL DEFAULT now(),
    acknowledged_at   timestamptz,
    acknowledged_by   uuid        REFERENCES users (id) ON DELETE SET NULL,
    resolved_at       timestamptz,
    last_evaluated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);
-- Deduplicação: no máximo um alerta ativo por (regra, servidor, serviço).
CREATE UNIQUE INDEX alerts_active_key ON alerts (
    rule_id, server_id, COALESCE(service_id, '00000000-0000-0000-0000-000000000000'::uuid)
) WHERE status <> 'resolved';
CREATE INDEX alerts_status_idx ON alerts (status, triggered_at DESC);
CREATE INDEX alerts_server_idx ON alerts (server_id, triggered_at DESC);
