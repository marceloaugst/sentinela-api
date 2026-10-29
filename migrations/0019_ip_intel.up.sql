-- Cache da reputação/geolocalização de IPs (AbuseIPDB). A consulta externa tem cota diária; o cache evita repeti-la.
CREATE TABLE ip_intel (
    ip               inet PRIMARY KEY,
    country_code     text NOT NULL DEFAULT '',
    isp              text NOT NULL DEFAULT '',
    usage_type       text NOT NULL DEFAULT '',
    domain           text NOT NULL DEFAULT '',
    abuse_score      integer NOT NULL DEFAULT 0,
    total_reports    integer NOT NULL DEFAULT 0,
    is_tor           boolean NOT NULL DEFAULT false,
    last_reported_at timestamptz,
    fetched_at       timestamptz NOT NULL
);
CREATE INDEX ip_intel_fetched_at_idx ON ip_intel (fetched_at);

-- Consultas feitas por dia (UTC), para respeitar a cota do plano.
CREATE TABLE ip_intel_usage (
    day   date PRIMARY KEY,
    calls integer NOT NULL DEFAULT 0
);
