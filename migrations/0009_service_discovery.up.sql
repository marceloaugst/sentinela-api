-- Descoberta automática de serviços do sistema (ssh, cron, nginx, redis, postgresql...).
-- O agente envia um retrato completo a cada mudança; a API guarda o último por (servidor, serviço).
CREATE TABLE service_discovery (
    server_id         uuid        NOT NULL REFERENCES servers (id),
    key               text        NOT NULL,
    status            text        NOT NULL CHECK (status IN ('available', 'stopped', 'not_found')),
    source            text        NOT NULL DEFAULT '' CHECK (source IN ('', 'systemd', 'process', 'docker')),
    unit              text        NOT NULL DEFAULT '',
    checked_at        timestamptz NOT NULL,
    status_changed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, key)
);
