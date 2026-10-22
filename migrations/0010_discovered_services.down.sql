DELETE FROM alerts WHERE service_id IN (SELECT id FROM monitored_services WHERE service_type = 'discovered');
DELETE FROM monitored_services WHERE service_type = 'discovered';
DROP INDEX monitored_services_discovery_key;
ALTER TABLE monitored_services DROP COLUMN discovery_key;
ALTER TABLE monitored_services DROP CONSTRAINT monitored_services_service_type_check;
ALTER TABLE monitored_services ADD CONSTRAINT monitored_services_service_type_check
    CHECK (service_type IN ('http', 'systemd', 'tcp'));
