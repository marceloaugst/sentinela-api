package logstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"sentinela/internal/procs"
)

func (s *Store) procTable() string { return s.cfg.Database + ".process_top" }

// Histórico dos maiores consumidores: a cada relatório do agente, os processos que mais usam CPU e memória.
const schemaProcTable = `CREATE TABLE IF NOT EXISTS %s (
	ts           DateTime64(3, 'UTC'),
	server_id    UUID,
	pid          UInt32,
	name         String,
	user         String,
	cpu_percent  Float32,
	memory_bytes UInt64
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (server_id, ts, pid)
TTL toDateTime(ts) + INTERVAL %d DAY
SETTINGS non_replicated_deduplication_window = 1000`

func (s *Store) initProcs(ctx context.Context) error {
	if err := s.exec(ctx, fmt.Sprintf(schemaProcTable, s.procTable(), s.cfg.RetentionDays), nil); err != nil {
		return err
	}
	return s.exec(ctx, fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY", s.procTable(), s.cfg.RetentionDays), nil)
}

const chTime = "2006-01-02 15:04:05.000"

// InsertProcTop grava as amostras de uma leitura. Reenviar a mesma leitura não duplica (token = servidor + instante).
func (s *Store) InsertProcTop(ctx context.Context, serverID string, samples []procs.TopSample) error {
	if len(samples) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	type row struct {
		TS          string  `json:"ts"`
		ServerID    string  `json:"server_id"`
		PID         int     `json:"pid"`
		Name        string  `json:"name"`
		User        string  `json:"user"`
		CPUPercent  float64 `json:"cpu_percent"`
		MemoryBytes int64   `json:"memory_bytes"`
	}
	for _, m := range samples {
		if err := enc.Encode(row{m.At.UTC().Format(chTime), serverID, m.PID, m.Name, m.User, m.CPUPercent, m.MemoryBytes}); err != nil {
			return err
		}
	}
	q := url.Values{}
	q.Set("query", "INSERT INTO "+s.procTable()+" FORMAT JSONEachRow")
	q.Set("insert_deduplication_token", fmt.Sprintf("proc:%s:%d", serverID, samples[0].At.UnixMilli()))
	q.Set("date_time_input_format", "best_effort")
	_, err := s.do(ctx, q, &buf)
	return err
}

// ProcTopRange devolve as amostras do servidor entre from e to, da mais antiga para a mais nova (no máximo limit linhas).
func (s *Store) ProcTopRange(ctx context.Context, serverID string, from, to time.Time, limit int) ([]procs.TopSample, error) {
	sql := fmt.Sprintf(`SELECT toString(ts) AS at, pid, name, user, cpu_percent, memory_bytes FROM %s
		WHERE server_id = {sid:UUID} AND ts >= {from:DateTime64(3,'UTC')} AND ts <= {to:DateTime64(3,'UTC')}
		ORDER BY ts, cpu_percent DESC, pid LIMIT {lim:UInt32} FORMAT JSONEachRow`, s.procTable())
	raw, err := s.query(ctx, sql, map[string]string{"sid": serverID, "from": from.UTC().Format(chTime), "to": to.UTC().Format(chTime), "lim": fmt.Sprint(limit)})
	if err != nil {
		return nil, err
	}
	var out []procs.TopSample
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			TS          string  `json:"at"`
			PID         int     `json:"pid"`
			Name        string  `json:"name"`
			User        string  `json:"user"`
			CPUPercent  float64 `json:"cpu_percent"`
			MemoryBytes int64   `json:"memory_bytes"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		at, err := time.ParseInLocation("2006-01-02 15:04:05.999", r.TS, time.UTC)
		if err != nil {
			return nil, err
		}
		out = append(out, procs.TopSample{At: at, PID: r.PID, Name: r.Name, User: r.User, CPUPercent: round1(r.CPUPercent), MemoryBytes: r.MemoryBytes})
	}
	return out, nil
}

// ProcCulprits agrega a janela por nome de processo (workers do mesmo programa somam) e devolve os n maiores do tipo
// (cpu ou memory) com a média e o pico, junto com quantas leituras a janela tem. A média divide pelo total de leituras,
// então um processo que só apareceu em parte da janela pesa menos.
func (s *Store) ProcCulprits(ctx context.Context, serverID string, from, to time.Time, kind string, n int) ([]procs.Culprit, int, error) {
	order := "cpu_avg"
	if kind == procs.KindMemory {
		order = "mem_avg"
	}
	sql := fmt.Sprintf(`WITH (SELECT uniqExact(ts) FROM %[1]s WHERE server_id = {sid:UUID} AND ts >= {from:DateTime64(3,'UTC')} AND ts <= {to:DateTime64(3,'UTC')}) AS n
		SELECT name, any(user) AS user, sum(c) / n AS cpu_avg, max(c) AS cpu_peak, sum(m) / n AS mem_avg, max(m) AS mem_peak, n AS samples
		FROM (SELECT ts, name, any(user) AS user, sum(cpu_percent) AS c, sum(memory_bytes) AS m FROM %[1]s
			WHERE server_id = {sid:UUID} AND ts >= {from:DateTime64(3,'UTC')} AND ts <= {to:DateTime64(3,'UTC')} GROUP BY ts, name)
		GROUP BY name ORDER BY %[2]s DESC LIMIT {n:UInt32} FORMAT JSONEachRow`, s.procTable(), order)
	raw, err := s.query(ctx, sql, map[string]string{"sid": serverID, "from": from.UTC().Format(chTime), "to": to.UTC().Format(chTime), "n": fmt.Sprint(n)})
	if err != nil {
		return nil, 0, err
	}
	var out []procs.Culprit
	samples := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			Name    string  `json:"name"`
			User    string  `json:"user"`
			CPUAvg  float64 `json:"cpu_avg"`
			CPUPeak float64 `json:"cpu_peak"`
			MemAvg  float64 `json:"mem_avg"`
			MemPeak float64 `json:"mem_peak"`
			Samples int     `json:"samples"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, 0, err
		}
		samples = r.Samples
		out = append(out, procs.Culprit{Name: r.Name, User: r.User, CPUPercent: round1(r.CPUAvg), CPUPeak: round1(r.CPUPeak),
			MemoryBytes: int64(r.MemAvg), MemoryPeakBytes: int64(r.MemPeak)})
	}
	return out, samples, nil
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }
