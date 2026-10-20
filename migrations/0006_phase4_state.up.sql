-- Serviços: todo serviço pertence a um servidor (alertas exigem servidor); campos de estado da última verificação.
ALTER TABLE monitored_services
    ALTER COLUMN server_id SET NOT NULL,
    ADD COLUMN last_error            text,
    ADD COLUMN last_latency_ms       integer,
    ADD COLUMN last_status_code      integer,
    ADD COLUMN consecutive_failures  integer     NOT NULL DEFAULT 0,
    ADD COLUMN status_changed_at     timestamptz,
    ADD COLUMN next_check_at         timestamptz NOT NULL DEFAULT now();
CREATE UNIQUE INDEX monitored_services_name_key ON monitored_services (server_id, lower(name)) WHERE deleted_at IS NULL;
-- Fila de verificações centrais (HTTP) vencidas.
CREATE INDEX monitored_services_due_idx ON monitored_services (next_check_at)
    WHERE deleted_at IS NULL AND service_type = 'http';

-- Regras: exclusão lógica (alertas e incidentes históricos referenciam a regra).
ALTER TABLE alert_rules ADD COLUMN deleted_at timestamptz;

-- Alertas: estado persistido da máquina de estados (sobrevive a reinícios).
ALTER TABLE alerts
    ADD COLUMN pending_since    timestamptz, -- condição verdadeira desde (estado pending)
    ADD COLUMN recovering_since timestamptz, -- condição falsa desde (alerta ainda ativo, aguardando recovery_seconds)
    ADD COLUMN resolved_reason  text;        -- recovered | manual | rule_disabled | rule_deleted | server_inactive ...
