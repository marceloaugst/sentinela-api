ALTER TABLE alerts DROP COLUMN resolved_reason, DROP COLUMN recovering_since, DROP COLUMN pending_since;
ALTER TABLE alert_rules DROP COLUMN deleted_at;
DROP INDEX monitored_services_due_idx;
DROP INDEX monitored_services_name_key;
ALTER TABLE monitored_services
    DROP COLUMN next_check_at, DROP COLUMN status_changed_at, DROP COLUMN consecutive_failures,
    DROP COLUMN last_status_code, DROP COLUMN last_latency_ms, DROP COLUMN last_error,
    ALTER COLUMN server_id DROP NOT NULL;
