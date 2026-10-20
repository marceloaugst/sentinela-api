package dashboard

import (
	"context"
	"time"

	"sentinela/internal/metrics"
	"sentinela/internal/servers"
)

// AvailabilityWindow é a janela do indicador de disponibilidade do resumo do servidor.
const AvailabilityWindow = 24 * time.Hour

type LoadAverage struct {
	M1  *float64 `json:"m1"`
	M5  *float64 `json:"m5"`
	M15 *float64 `json:"m15"`
}

type MemoryInfo struct {
	TotalBytes     int64    `json:"total_bytes"`
	UsedBytes      int64    `json:"used_bytes"`
	AvailableBytes int64    `json:"available_bytes"`
	UsedPercent    *float64 `json:"used_percent"`
	SwapTotalBytes int64    `json:"swap_total_bytes"`
	SwapUsedBytes  int64    `json:"swap_used_bytes"`
}

type NetworkRate struct {
	RXBytesPerSec float64 `json:"rx_bytes_per_sec"`
	TXBytesPerSec float64 `json:"tx_bytes_per_sec"`
}

type Latest struct {
	CollectedAt     time.Time   `json:"collected_at"`
	ReceivedAt      time.Time   `json:"received_at"`
	CPUUsagePercent float64     `json:"cpu_usage_percent"`
	CPUCount        *int        `json:"cpu_count"`
	LoadAverage     LoadAverage `json:"load_average"`
	Memory          MemoryInfo  `json:"memory"`
	UptimeSeconds   *int64      `json:"uptime_seconds"`
	// Taxa entre as duas últimas amostras; nula se o par não for confiável (reset, lacuna, sem dados).
	Network *NetworkRate `json:"network"`
}

type ServiceCounts struct {
	Total    int `json:"total"`
	Up       int `json:"up"`
	Down     int `json:"down"`
	Degraded int `json:"degraded"`
	Unknown  int `json:"unknown"`
}

type Availability struct {
	WindowSeconds int64 `json:"window_seconds"`
	// Nulo quando a janela efetiva (desde o cadastro) é curta demais para ser significativa.
	Percent *float64 `json:"percent"`
}

type ServerSummary struct {
	Server    servers.Server `json:"server"`
	Latest    *Latest        `json:"latest"`
	Disks     []servers.Disk `json:"disks"`
	Alerts    AlertCounts    `json:"alerts"`
	Incidents struct {
		Open int `json:"open"`
	} `json:"incidents"`
	Services     ServiceCounts `json:"services"`
	Availability Availability  `json:"availability"`
}

// Janela mínima para reportar disponibilidade.
const minAvailabilityWindow = time.Minute

func (r *Repository) ServerSummary(ctx context.Context, srv *servers.Repository, mt *metrics.Repository, id string, now time.Time) (ServerSummary, error) {
	var s ServerSummary
	var err error
	if s.Server, err = srv.Get(ctx, id); err != nil {
		return s, err
	}
	if s.Disks, err = srv.Disks(ctx, id); err != nil {
		return s, err
	}

	samples, err := mt.Latest(ctx, id, 2)
	if err != nil {
		return s, err
	}
	if len(samples) > 0 {
		l := samples[0]
		s.Latest = &Latest{
			CollectedAt: l.CollectedAt, ReceivedAt: l.ReceivedAt, CPUUsagePercent: l.CPUPercent, CPUCount: l.CPUCount,
			LoadAverage:   LoadAverage{M1: l.Load1, M5: l.Load5, M15: l.Load15},
			UptimeSeconds: l.Uptime,
			Memory: MemoryInfo{
				TotalBytes: l.MemTotal, UsedBytes: l.MemUsed, AvailableBytes: l.MemAvail,
				UsedPercent: pct(l.MemUsed, l.MemTotal), SwapTotalBytes: l.SwapTotal, SwapUsedBytes: l.SwapUsed,
			},
		}
		if len(samples) == 2 {
			p := samples[1]
			if l.NetRX != nil && l.NetTX != nil && p.NetRX != nil && p.NetTX != nil {
				if rate, ok := metrics.CalcRate(
					metrics.NetSample{At: p.CollectedAt, RX: *p.NetRX, TX: *p.NetTX},
					metrics.NetSample{At: l.CollectedAt, RX: *l.NetRX, TX: *l.NetTX}); ok {
					s.Latest.Network = &NetworkRate{RXBytesPerSec: rate.RXBytesPerSec, TXBytesPerSec: rate.TXBytesPerSec}
				}
			}
		}
	}

	err = r.pool.QueryRow(ctx, `SELECT
		  count(*) FILTER (WHERE status IN ('firing','acknowledged')),
		  count(*) FILTER (WHERE status IN ('firing','acknowledged') AND severity = 'critical'),
		  count(*) FILTER (WHERE status IN ('firing','acknowledged') AND severity = 'warning'),
		  count(*) FILTER (WHERE status IN ('firing','acknowledged') AND severity = 'info')
		FROM alerts WHERE server_id = $1`, id).
		Scan(&s.Alerts.Active, &s.Alerts.Critical, &s.Alerts.Warning, &s.Alerts.Info)
	if err != nil {
		return s, err
	}
	if err = r.pool.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE server_id = $1 AND status = 'open'`, id).
		Scan(&s.Incidents.Open); err != nil {
		return s, err
	}
	if err = r.pool.QueryRow(ctx, `SELECT count(*),
		  count(*) FILTER (WHERE status = 'up'), count(*) FILTER (WHERE status = 'down'),
		  count(*) FILTER (WHERE status = 'degraded'), count(*) FILTER (WHERE status = 'unknown')
		FROM monitored_services WHERE server_id = $1 AND deleted_at IS NULL`, id).
		Scan(&s.Services.Total, &s.Services.Up, &s.Services.Down, &s.Services.Degraded, &s.Services.Unknown); err != nil {
		return s, err
	}

	// Disponibilidade: janela de 24h, mas não antes do cadastro do servidor.
	to := now.UTC()
	from := to.Add(-AvailabilityWindow)
	if s.Server.CreatedAt.After(from) {
		from = s.Server.CreatedAt.UTC()
	}
	s.Availability.WindowSeconds = int64(to.Sub(from).Seconds())
	if to.Sub(from) >= minAvailabilityWindow {
		timeout := r.heartbeatTimeout
		times, err := mt.SampleTimes(ctx, id, from.Add(-timeout), to)
		if err != nil {
			return s, err
		}
		v := metrics.Availability(times, from, to, timeout)
		s.Availability.Percent = &v
	}
	return s, nil
}
