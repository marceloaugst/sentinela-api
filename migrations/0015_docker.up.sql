-- Retrato dos containers Docker do servidor, enviado pelo agente (um registro por servidor, substituído a cada envio).
-- status: ok | not_installed | no_access | unavailable (veja internal/dockerhost).
CREATE TABLE docker_snapshots (
    server_id  uuid        PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    status     text        NOT NULL CHECK (status IN ('ok', 'not_installed', 'no_access', 'unavailable')),
    message    text        NOT NULL DEFAULT '',
    checked_at timestamptz NOT NULL,
    containers jsonb       NOT NULL DEFAULT '[]'
);

-- Comandos de container (iniciar, reiniciar) reaproveitam service_commands: target guarda o id do container
-- (vazio = comando de serviço systemd). O limite de um comando em andamento passa a ser por container.
ALTER TABLE service_commands ADD COLUMN target text NOT NULL DEFAULT '';
DROP INDEX service_commands_active_key;
CREATE UNIQUE INDEX service_commands_active_key ON service_commands (server_id, service_key, target)
    WHERE status IN ('pending', 'running');
