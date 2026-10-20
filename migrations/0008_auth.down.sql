DROP INDEX audit_logs_actor_idx;
DROP INDEX audit_logs_action_idx;
DROP INDEX login_attempts_email_ip_idx;
ALTER TABLE sessions DROP COLUMN revoked_reason;
ALTER TABLE users DROP COLUMN last_login_at, DROP COLUMN password_changed_at;
