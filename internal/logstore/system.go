package logstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"sentinela/internal/sysmetrics"
)

func (s *Store) systemTable() string { return s.cfg.Database + ".system_metrics" }

const schemaSystemTable = `CREATE TABLE IF NOT EXISTS %s (
	ts        DateTime64(3, 'UTC'),
	server_id UUID,
	metric    LowCardinality(String),
	subject   String,
	value     Float64
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (server_id, metric, subject, ts)
TTL toDateTime(ts) + INTERVAL %d DAY
SETTINGS non_replicated_deduplication_window = 1000`

// initSystem cria a tabela das métricas de sistema (chamada por Init).
func (s *Store) initSystem(ctx context.Context) error {
	if err := s.exec(ctx, fmt.Sprintf(schemaSystemTable, s.systemTable(), s.cfg.RetentionDays), nil); err != nil {
		return err
	}
	return s.exec(ctx, fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY", s.systemTable(), s.cfg.RetentionDays), nil)
}

// InsertSystem grava o lote; batchID vira o token de deduplicação (reenviar não duplica).
func (s *Store) InsertSystem(ctx context.Context, serverID, batchID string, samples []sysmetrics.Sample) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	type row struct {
		TS       string  `json:"ts"`
		ServerID string  `json:"server_id"`
		Metric   string  `json:"metric"`
		Subject  string  `json:"subject"`
		Value    float64 `json:"value"`
	}
	for _, m := range samples {
		if err := enc.Encode(row{m.Time.UTC().Format("2006-01-02 15:04:05.000"), serverID, m.Metric, m.Subject, m.Value}); err != nil {
			return err
		}
	}
	q := url.Values{}
	q.Set("query", "INSERT INTO "+s.systemTable()+" FORMAT JSONEachRow")
	q.Set("insert_deduplication_token", "sys:"+serverID+":"+batchID)
	q.Set("date_time_input_format", "best_effort")
	asyncInsert(q)
	_, err := s.do(ctx, q, &buf)
	return err
}

// SystemValue é o estado atual de uma métrica de um servidor: o último valor e a soma na janela.
type SystemValue struct {
	ServerID string
	Metric   string
	Subject  string
	Latest   float64
	Sum      float64
}

// LatestSystem devolve, por (servidor, métrica, assunto), o último valor e a soma das amostras da janela.
// Assuntos sem amostra na janela não aparecem (dado velho nunca vira alerta nem resolve alerta).
func (s *Store) LatestSystem(ctx context.Context, window time.Duration) ([]SystemValue, error) {
	sql := fmt.Sprintf(`SELECT toString(server_id) AS server_id, metric, subject, argMax(value, ts) AS latest, sum(value) AS total
		FROM %s WHERE ts >= now64(3) - toIntervalSecond({win:UInt32})
		GROUP BY server_id, metric, subject FORMAT JSONEachRow`, s.systemTable())
	raw, err := s.query(ctx, sql, map[string]string{"win": fmt.Sprint(int(window.Seconds()))})
	if err != nil {
		return nil, err
	}
	var out []SystemValue
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			ServerID string  `json:"server_id"`
			Metric   string  `json:"metric"`
			Subject  string  `json:"subject"`
			Latest   float64 `json:"latest"`
			Total    float64 `json:"total"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		out = append(out, SystemValue{r.ServerID, r.Metric, r.Subject, r.Latest, r.Total})
	}
	return out, nil
}
