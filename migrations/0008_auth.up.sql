ALTER TABLE users
    ADD COLUMN password_changed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_login_at       timestamptz;

ALTER TABLE sessions ADD COLUMN revoked_reason text; -- logout | logout_all | password_changed | user_deactivated | admin_revoked

-- Consultas de bloqueio por (e-mail, IP) e por IP.
CREATE INDEX login_attempts_email_ip_idx ON login_attempts (email, ip, attempted_at DESC);

-- Consulta da trilha de auditoria.
CREATE INDEX audit_logs_action_idx ON audit_logs (action, created_at DESC);
CREATE INDEX audit_logs_actor_idx  ON audit_logs (actor_user_id, created_at DESC);
