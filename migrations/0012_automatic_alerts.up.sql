-- Alertas e incidentes automáticos: as regras passam a vir de um catálogo fixo no código (alerts.Catalog),
-- sincronizado com esta tabela a cada inicialização da API. O cadastro manual deixou de existir.
ALTER TABLE alert_rules
    ADD COLUMN code        text,                                                    -- identificador estável da regra do catálogo
    ADD COLUMN description text     NOT NULL DEFAULT '',
    ADD COLUMN priority    smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 4); -- P1 crítico ... P4 informativo
CREATE UNIQUE INDEX alert_rules_code_key ON alert_rules (code);

ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_name_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_name_check CHECK (metric_name IN
    ('cpu_usage_percent', 'memory_used_percent', 'disk_used_percent', 'load_average_1m',
     'server_offline', 'service_down', 'swap_used_percent', 'load_per_cpu'));

-- Incidentes: prioridade herdada da regra e contagem de reincidências (incidentes anteriores da mesma
-- combinação servidor/regra/serviço nas últimas 24 h).
ALTER TABLE incidents
    ADD COLUMN priority         smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 4),
    ADD COLUMN recurrence_count integer  NOT NULL DEFAULT 0 CHECK (recurrence_count >= 0);
UPDATE incidents i SET priority = CASE i.severity WHEN 'critical' THEN 1 WHEN 'warning' THEN 3 ELSE 4 END;
