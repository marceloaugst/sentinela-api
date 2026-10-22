ALTER TABLE incidents DROP COLUMN recurrence_count, DROP COLUMN priority;
DELETE FROM alert_rules WHERE metric_name IN ('swap_used_percent', 'load_per_cpu')
    AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.rule_id = alert_rules.id)
    AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.rule_id = alert_rules.id);
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_name_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_name_check CHECK (metric_name IN
    ('cpu_usage_percent', 'memory_used_percent', 'disk_used_percent', 'load_average_1m', 'server_offline', 'service_down'));
DROP INDEX alert_rules_code_key;
ALTER TABLE alert_rules DROP COLUMN priority, DROP COLUMN description, DROP COLUMN code;
