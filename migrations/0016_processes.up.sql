-- Retrato dos processos do servidor (CPU e memória), enviado pelo agente: um registro por servidor, substituído a cada envio.
CREATE TABLE process_snapshots (
    server_id          uuid        PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    checked_at         timestamptz NOT NULL,
    cpus               integer     NOT NULL CHECK (cpus > 0),
    memory_total_bytes bigint      NOT NULL DEFAULT 0,
    total              integer     NOT NULL DEFAULT 0,
    processes          jsonb       NOT NULL DEFAULT '[]'
);

-- Encerrar processo reaproveita service_commands: service_key = 'process', target = "<pid>:<início>" e a ação é
-- terminate (SIGTERM) ou kill (SIGKILL). O limite de um comando em andamento por (servidor, serviço, alvo) vale por processo.
ALTER TABLE service_commands DROP CONSTRAINT service_commands_action_check;
ALTER TABLE service_commands ADD CONSTRAINT service_commands_action_check
    CHECK (action IN ('start', 'stop', 'restart', 'terminate', 'kill'));
