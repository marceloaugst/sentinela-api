-- `status` é o estado ADMINISTRATIVO (active/maintenance/disabled).
-- A conectividade (online/offline) é calculada a partir de last_seen_at e do
-- limite AGENT_HEARTBEAT_TIMEOUT_SECONDS; nunca é gravada manualmente.
CREATE TABLE servers (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    hostname                 text        NOT NULL CHECK (length(hostname) BETWEEN 1 AND 253),
    operating_system         text,
    operating_system_version text,
    architecture             text,
    agent_version            text,
    status                   text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'maintenance', 'disabled')),
    last_seen_at             timestamptz,
    deleted_at               timestamptz, -- exclusão lógica; histórico é preservado
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX servers_name_key ON servers (lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX servers_hostname_idx ON servers (lower(hostname)) WHERE deleted_at IS NULL;
CREATE INDEX servers_last_seen_idx ON servers (last_seen_at) WHERE deleted_at IS NULL;

CREATE TABLE agent_credentials (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id    uuid        NOT NULL REFERENCES servers (id),
    token_hash   bytea       NOT NULL, -- SHA-256 do token (256 bits de entropia); o token nunca é guardado
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz
);
CREATE UNIQUE INDEX agent_credentials_token_hash_key ON agent_credentials (token_hash);
CREATE INDEX agent_credentials_server_idx ON agent_credentials (server_id) WHERE revoked_at IS NULL;
