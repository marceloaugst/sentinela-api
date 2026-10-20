-- (server_id, collected_at) único: protege contra reenvio/replay da mesma amostra.
-- Contadores de rede são ACUMULADOS; taxas são calculadas na consulta por diferença
-- entre amostras consecutivas (descartando resets de contador).
-- Para escala, a tabela pode ser convertida em particionada por collected_at (ver docs).
CREATE TABLE server_metrics (
    id                      bigint GENERATED ALWAYS AS IDENTITY,
    server_id               uuid             NOT NULL REFERENCES servers (id),
    collected_at            timestamptz      NOT NULL,
    received_at             timestamptz      NOT NULL DEFAULT now(),
    cpu_usage_percent       double precision NOT NULL CHECK (cpu_usage_percent BETWEEN 0 AND 100),
    cpu_count               integer          CHECK (cpu_count > 0),
    load_average_1m         double precision CHECK (load_average_1m >= 0),
    load_average_5m         double precision CHECK (load_average_5m >= 0),
    load_average_15m        double precision CHECK (load_average_15m >= 0),
    memory_total_bytes      bigint           NOT NULL CHECK (memory_total_bytes >= 0),
    memory_used_bytes       bigint           NOT NULL CHECK (memory_used_bytes >= 0),
    memory_available_bytes  bigint           NOT NULL CHECK (memory_available_bytes >= 0),
    swap_total_bytes        bigint           NOT NULL DEFAULT 0 CHECK (swap_total_bytes >= 0),
    swap_used_bytes         bigint           NOT NULL DEFAULT 0 CHECK (swap_used_bytes >= 0),
    network_rx_bytes_total  bigint           CHECK (network_rx_bytes_total >= 0),
    network_tx_bytes_total  bigint           CHECK (network_tx_bytes_total >= 0),
    uptime_seconds          bigint           CHECK (uptime_seconds >= 0),
    PRIMARY KEY (server_id, collected_at)
);
CREATE INDEX server_metrics_collected_idx ON server_metrics (collected_at);

CREATE TABLE server_disks (
    server_id       uuid        NOT NULL REFERENCES servers (id),
    mount_point     text        NOT NULL,
    filesystem      text,
    total_bytes     bigint      NOT NULL CHECK (total_bytes >= 0),
    used_bytes      bigint      NOT NULL CHECK (used_bytes >= 0),
    available_bytes bigint      NOT NULL CHECK (available_bytes >= 0),
    collected_at    timestamptz NOT NULL,
    -- Um registro "atual" por ponto de montagem: a coleta faz UPSERT, sem duplicar.
    PRIMARY KEY (server_id, mount_point)
);
