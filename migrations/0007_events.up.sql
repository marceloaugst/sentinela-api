-- Log de eventos duráveis para o stream SSE. Gravado na MESMA transação da mudança de estado
-- (se a transação desfaz, o evento também), permite reconexão com Last-Event-ID e a distribuição
-- entre instâncias da API (cada uma lê o log; NOTIFY apenas acelera a entrega).
CREATE TABLE events (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type       text        NOT NULL,
    server_id  uuid,       -- para filtrar por servidor; sem FK: o log é transitório
    data       jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX events_created_idx ON events (created_at);

-- Maior id já removido pela retenção: um cliente com Last-Event-ID abaixo disso perdeu eventos
-- e precisa ressincronizar (não dá para inferir isso só dos ids, que têm lacunas normais).
CREATE TABLE event_log_state (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    purged_until bigint  NOT NULL DEFAULT 0
);
INSERT INTO event_log_state DEFAULT VALUES;

-- Último estado de conectividade observado, para detectar TRANSIÇÕES online/offline.
-- (A API continua calculando o estado a partir de last_seen_at; esta coluna só serve aos eventos.)
ALTER TABLE servers ADD COLUMN connection_state text NOT NULL DEFAULT 'unknown'
    CHECK (connection_state IN ('unknown', 'online', 'offline'));
UPDATE servers SET connection_state = CASE
    WHEN last_seen_at IS NULL THEN 'unknown'
    WHEN last_seen_at >= now() - interval '60 seconds' THEN 'online'
    ELSE 'offline' END;
