package metrics

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrTooManyPoints: a consulta geraria mais pontos que MaxPoints (típico de 'raw' com
// amostragem muito densa). O cliente deve usar um intervalo maior.
var ErrTooManyPoints = errors.New("pontos demais para o período")

// Stat resume uma métrica em um balde. Em amostras originais min = avg = max.
// Valores ausentes (ex.: swap inexistente, primeira amostra sem taxa) são nulos.
type Stat struct {
	Min *float64 `json:"min"`
	Avg *float64 `json:"avg"`
	Max *float64 `json:"max"`
}

// Point é um balde de tempo (ou uma amostra original). Baldes sem amostras são omitidos.
type Point struct {
	T                    time.Time `json:"t"`
	Samples              int       `json:"samples"`
	CPUUsagePercent      Stat      `json:"cpu_usage_percent"`
	MemoryUsedPercent    Stat      `json:"memory_used_percent"`
	MemoryUsedBytes      Stat      `json:"memory_used_bytes"`
	LoadAverage1m        Stat      `json:"load_average_1m"`
	SwapUsedPercent      Stat      `json:"swap_used_percent"`
	NetworkRXBytesPerSec Stat      `json:"network_rx_bytes_per_sec"`
	NetworkTXBytesPerSec Stat      `json:"network_tx_bytes_per_sec"`
}

func (p *Point) stats() []*Stat {
	return []*Stat{&p.CPUUsagePercent, &p.MemoryUsedPercent, &p.MemoryUsedBytes, &p.LoadAverage1m,
		&p.SwapUsedPercent, &p.NetworkRXBytesPerSec, &p.NetworkTXBytesPerSec}
}

const binOrigin = "TIMESTAMPTZ '2000-01-01 00:00:00+00'"

// Taxas de rede: calculadas entre amostras CONSECUTIVAS, descartando o par quando há
// lacuna > MaxSampleGap, contador menor que o anterior (reset) ou valores ausentes.
// Espelha metrics.CalcRate (verificado por teste de integração).
const seriesSQL = `
WITH s AS (
  SELECT collected_at,
    cpu_usage_percent AS cpu,
    CASE WHEN memory_total_bytes > 0 THEN memory_used_bytes::float8 / memory_total_bytes * 100 END AS mem_pct,
    memory_used_bytes::float8 AS mem_bytes,
    load_average_1m AS load1,
    CASE WHEN swap_total_bytes > 0 THEN swap_used_bytes::float8 / swap_total_bytes * 100 END AS swap_pct,
    network_rx_bytes_total AS rx, network_tx_bytes_total AS tx,
    lag(collected_at) OVER w AS pt,
    lag(network_rx_bytes_total) OVER w AS prx,
    lag(network_tx_bytes_total) OVER w AS ptx
  FROM server_metrics
  WHERE server_id = $1 AND collected_at >= $2 AND collected_at < $3
  WINDOW w AS (ORDER BY collected_at)
), r AS (
  SELECT *,
    CASE WHEN pt IS NOT NULL AND rx IS NOT NULL AND tx IS NOT NULL AND prx IS NOT NULL AND ptx IS NOT NULL
          AND collected_at - pt <= interval '10 minutes' AND rx >= prx AND tx >= ptx
         THEN extract(epoch FROM collected_at - pt)::float8 END AS dt
  FROM s
), p AS (
  SELECT *, (rx - prx)::float8 / NULLIF(dt, 0) AS rxr, (tx - ptx)::float8 / NULLIF(dt, 0) AS txr FROM r
)
SELECT %s AS t, count(*)::int,
  min(cpu), avg(cpu), max(cpu),
  min(mem_pct), avg(mem_pct), max(mem_pct),
  min(mem_bytes), avg(mem_bytes), max(mem_bytes),
  min(load1), avg(load1), max(load1),
  min(swap_pct), avg(swap_pct), max(swap_pct),
  min(rxr), avg(rxr), max(rxr),
  min(txr), avg(txr), max(txr)
FROM p GROUP BY 1 ORDER BY 1 LIMIT %s`

// ServerSeries devolve a série de um servidor no período [From, To).
func (r *Repository) ServerSeries(ctx context.Context, serverID string, rg Range) ([]Point, error) {
	args := []any{serverID, rg.From, rg.To}
	var q string
	if rg.Interval.IsRaw() {
		args = append(args, MaxPoints+1)
		q = fmt.Sprintf(seriesSQL, "collected_at", "$4")
	} else {
		args = append(args, rg.Interval.Dur.Seconds(), MaxPoints+1)
		q = fmt.Sprintf(seriesSQL, "date_bin(make_interval(secs => $4), collected_at, "+binOrigin+")", "$5")
	}
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Point{}
	for rows.Next() {
		var p Point
		dst := []any{&p.T, &p.Samples}
		for _, s := range p.stats() {
			dst = append(dst, &s.Min, &s.Avg, &s.Max)
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > MaxPoints {
		return nil, ErrTooManyPoints
	}
	return out, nil
}

// AggPoint é um balde agregado entre servidores.
type AggPoint struct {
	T       time.Time `json:"t"`
	Samples int       `json:"samples"`
	// Servidores distintos que enviaram dados no balde.
	Servers         int  `json:"servers"`
	CPUUsagePercent Stat `json:"cpu_usage_percent"`
	// Σ memória usada / Σ memória total das amostras do balde (ponderada por tamanho).
	MemoryUsedPercent *float64 `json:"memory_used_percent"`
	LoadAverage1m     Stat     `json:"load_average_1m"`
}

const dashSeriesSQL = `
SELECT date_bin(make_interval(secs => $4), x.collected_at, ` + binOrigin + `) AS t,
  count(*)::int, count(DISTINCT x.server_id)::int,
  min(x.cpu), avg(x.cpu), max(x.cpu),
  sum(x.mem_used)::float8 / NULLIF(sum(x.mem_total), 0) * 100,
  min(x.load1), avg(x.load1), max(x.load1)
FROM (
  SELECT m.server_id, m.collected_at, m.cpu_usage_percent AS cpu, m.memory_used_bytes AS mem_used,
         m.memory_total_bytes AS mem_total, m.load_average_1m AS load1
  FROM server_metrics m
  JOIN servers s ON s.id = m.server_id AND s.deleted_at IS NULL
  WHERE m.collected_at >= $1 AND m.collected_at < $2
    AND ($3::text[] IS NULL OR m.server_id = ANY($3::text[]::uuid[]))
) x
GROUP BY 1 ORDER BY 1 LIMIT $5`

// DashboardSeries agrega as amostras de vários servidores (todos, ou os de serverIDs).
func (r *Repository) DashboardSeries(ctx context.Context, rg Range, serverIDs []string) ([]AggPoint, error) {
	var ids any // NULL = todos
	if len(serverIDs) > 0 {
		ids = serverIDs
	}
	rows, err := r.pool.Query(ctx, dashSeriesSQL, rg.From, rg.To, ids, rg.Interval.Dur.Seconds(), MaxPoints+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AggPoint{}
	for rows.Next() {
		var p AggPoint
		if err := rows.Scan(&p.T, &p.Samples, &p.Servers,
			&p.CPUUsagePercent.Min, &p.CPUUsagePercent.Avg, &p.CPUUsagePercent.Max,
			&p.MemoryUsedPercent,
			&p.LoadAverage1m.Min, &p.LoadAverage1m.Avg, &p.LoadAverage1m.Max); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > MaxPoints {
		return nil, ErrTooManyPoints
	}
	return out, nil
}

// SampleTimes devolve os horários de RECEBIMENTO (relógio do servidor, confiável) das
// amostras em [from, to), em ordem, para o cálculo de disponibilidade.
func (r *Repository) SampleTimes(ctx context.Context, serverID string, from, to time.Time) ([]time.Time, error) {
	rows, err := r.pool.Query(ctx, `SELECT received_at FROM server_metrics
		WHERE server_id = $1 AND received_at >= $2 AND received_at < $3 ORDER BY received_at`, serverID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var t time.Time
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// LatestSample é uma amostra bruta; Latest devolve as mais recentes primeiro.
type LatestSample struct {
	CollectedAt time.Time
	ReceivedAt  time.Time
	CPUPercent  float64
	CPUCount    *int
	Load1       *float64
	Load5       *float64
	Load15      *float64
	MemTotal    int64
	MemUsed     int64
	MemAvail    int64
	SwapTotal   int64
	SwapUsed    int64
	NetRX       *int64
	NetTX       *int64
	Uptime      *int64
}

func (r *Repository) Latest(ctx context.Context, serverID string, n int) ([]LatestSample, error) {
	rows, err := r.pool.Query(ctx, `SELECT collected_at, received_at, cpu_usage_percent, cpu_count,
			load_average_1m, load_average_5m, load_average_15m,
			memory_total_bytes, memory_used_bytes, memory_available_bytes, swap_total_bytes, swap_used_bytes,
			network_rx_bytes_total, network_tx_bytes_total, uptime_seconds
		FROM server_metrics WHERE server_id = $1 ORDER BY collected_at DESC LIMIT $2`, serverID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LatestSample
	for rows.Next() {
		var s LatestSample
		if err := rows.Scan(&s.CollectedAt, &s.ReceivedAt, &s.CPUPercent, &s.CPUCount, &s.Load1, &s.Load5, &s.Load15,
			&s.MemTotal, &s.MemUsed, &s.MemAvail, &s.SwapTotal, &s.SwapUsed, &s.NetRX, &s.NetTX, &s.Uptime); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
