DELETE FROM service_commands WHERE target <> '';
DROP INDEX service_commands_active_key;
CREATE UNIQUE INDEX service_commands_active_key ON service_commands (server_id, service_key)
    WHERE status IN ('pending', 'running');
ALTER TABLE service_commands DROP COLUMN target;
DROP TABLE docker_snapshots;
