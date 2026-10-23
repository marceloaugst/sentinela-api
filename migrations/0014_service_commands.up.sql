-- Comandos de serviço (iniciar, parar, reiniciar) pedidos por usuários e executados pelo agente do servidor.
-- O agente só faz requisições de saída: ele busca os comandos pendentes e devolve o resultado.
CREATE TABLE service_commands (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id        uuid        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    service_key      text        NOT NULL,   -- chave do catálogo de descoberta (nginx, redis...)
    unit             text        NOT NULL,   -- unidade systemd conhecida no momento do pedido (informativo; o agente resolve a sua)
    action           text        NOT NULL CHECK (action IN ('start', 'stop', 'restart')),
    status           text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'expired')),
    -- Quem pediu. requested_by vira NULL se o usuário for removido; o rótulo e o IP continuam.
    requested_by     uuid        REFERENCES users (id) ON DELETE SET NULL,
    requested_actor  text        NOT NULL,
    requested_ip     inet,
    message          text        NOT NULL DEFAULT '',  -- texto curto do resultado (sanitizado pela API)
    created_at       timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz
);
-- No máximo um comando em andamento por serviço de um servidor.
CREATE UNIQUE INDEX service_commands_active_key ON service_commands (server_id, service_key)
    WHERE status IN ('pending', 'running');
CREATE INDEX service_commands_server_idx ON service_commands (server_id, created_at DESC);
