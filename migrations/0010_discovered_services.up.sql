-- Serviços descobertos automaticamente passam a ser serviços monitorados (tipo 'discovered'), para que
-- alertas, incidentes e notificações funcionem sem cadastro manual. O agente NÃO recebe esse tipo em
-- /agent/config: o estado vem do relatório de descoberta (POST /agent/discovery).
ALTER TABLE monitored_services DROP CONSTRAINT monitored_services_service_type_check;
ALTER TABLE monitored_services ADD CONSTRAINT monitored_services_service_type_check
    CHECK (service_type IN ('http', 'systemd', 'tcp', 'discovered'));
ALTER TABLE monitored_services ADD COLUMN discovery_key text;
-- Inclui linhas excluídas: um serviço descoberto que o usuário apagou não é recriado.
CREATE UNIQUE INDEX monitored_services_discovery_key ON monitored_services (server_id, discovery_key)
    WHERE discovery_key IS NOT NULL;

-- Regra padrão: avisa quando um serviço (inclusive os descobertos) fica indisponível por 2 minutos.
-- Só é criada se não existir nenhuma regra service_down; apagá-la depois é uma escolha que se mantém.
INSERT INTO alert_rules (name, metric_name, operator, threshold, severity, duration_seconds, recovery_seconds)
SELECT 'Serviço indisponível', 'service_down', '==', 1, 'critical', 120, 60
WHERE NOT EXISTS (SELECT 1 FROM alert_rules WHERE metric_name = 'service_down' AND deleted_at IS NULL);
