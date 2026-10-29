package ipintel

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cache é o armazenamento do Service (PostgreSQL em produção).
type cache interface {
	Get(ctx context.Context, ips []string) (map[string]Info, error)
	Put(ctx context.Context, in Info) error
	// Reserve conta uma consulta no dia e devolve false se a cota já foi atingida.
	Reserve(ctx context.Context, day time.Time, limit int) (bool, error)
}

type pgCache struct{ pool *pgxpool.Pool }

func (c pgCache) Get(ctx context.Context, ips []string) (map[string]Info, error) {
	rows, err := c.pool.Query(ctx, `SELECT host(ip), country_code, isp, usage_type, domain, abuse_score, total_reports,
		is_tor, last_reported_at, fetched_at FROM ip_intel WHERE ip = ANY($1::inet[])`, ips)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Info{}
	for rows.Next() {
		var in Info
		if err := rows.Scan(&in.IP, &in.CountryCode, &in.ISP, &in.UsageType, &in.Domain, &in.AbuseScore,
			&in.TotalReports, &in.IsTor, &in.LastReportedAt, &in.FetchedAt); err != nil {
			return nil, err
		}
		out[in.IP] = in
	}
	return out, rows.Err()
}

func (c pgCache) Put(ctx context.Context, in Info) error {
	_, err := c.pool.Exec(ctx, `INSERT INTO ip_intel (ip, country_code, isp, usage_type, domain, abuse_score, total_reports,
		is_tor, last_reported_at, fetched_at) VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (ip) DO UPDATE SET country_code = EXCLUDED.country_code, isp = EXCLUDED.isp,
		usage_type = EXCLUDED.usage_type, domain = EXCLUDED.domain, abuse_score = EXCLUDED.abuse_score,
		total_reports = EXCLUDED.total_reports, is_tor = EXCLUDED.is_tor,
		last_reported_at = EXCLUDED.last_reported_at, fetched_at = EXCLUDED.fetched_at`,
		in.IP, in.CountryCode, in.ISP, in.UsageType, in.Domain, in.AbuseScore, in.TotalReports, in.IsTor,
		in.LastReportedAt, in.FetchedAt)
	return err
}

func (c pgCache) Reserve(ctx context.Context, day time.Time, limit int) (bool, error) {
	var calls int
	err := c.pool.QueryRow(ctx, `INSERT INTO ip_intel_usage (day, calls) VALUES ($1, 1)
		ON CONFLICT (day) DO UPDATE SET calls = ip_intel_usage.calls + 1 WHERE ip_intel_usage.calls < $2
		RETURNING calls`, day.UTC().Format("2006-01-02"), limit).Scan(&calls)
	if err == pgx.ErrNoRows { // o WHERE impediu a atualização: cota atingida
		return false, nil
	}
	return err == nil, err
}

// Purge apaga entradas não renovadas há mais de olderThan (IPs que nunca mais apareceram) e a contagem antiga.
func Purge(ctx context.Context, pool *pgxpool.Pool, olderThan time.Duration, now time.Time) error {
	if _, err := pool.Exec(ctx, `DELETE FROM ip_intel WHERE fetched_at < $1`, now.Add(-olderThan)); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `DELETE FROM ip_intel_usage WHERE day < $1`, now.AddDate(0, 0, -7).UTC().Format("2006-01-02"))
	return err
}
