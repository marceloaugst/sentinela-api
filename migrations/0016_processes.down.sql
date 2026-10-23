DELETE FROM service_commands WHERE action IN ('terminate', 'kill');
ALTER TABLE service_commands DROP CONSTRAINT service_commands_action_check;
ALTER TABLE service_commands ADD CONSTRAINT service_commands_action_check CHECK (action IN ('start', 'stop', 'restart'));
DROP TABLE process_snapshots;
