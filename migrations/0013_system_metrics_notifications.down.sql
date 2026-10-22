DROP TABLE notifications;
DELETE FROM alert_rules WHERE metric_name IN ('oom_kills_10m', 'inode_used_percent', 'disk_latency_ms', 'ntp_unsynchronized',
        'security_updates', 'cert_days_left')
    AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.rule_id = alert_rules.id)
    AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.rule_id = alert_rules.id);
ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_name_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_name_check CHECK (metric_name IN
    ('cpu_usage_percent', 'memory_used_percent', 'disk_used_percent', 'load_average_1m',
     'server_offline', 'service_down', 'swap_used_percent', 'load_per_cpu'));
