// Package logstore grava e consulta logs no ClickHouse pela interface HTTP (sem driver nativo: menos
// dependências). Valores de filtro SEMPRE vão como parâmetros tipados (param_*), nunca concatenados ao SQL.
package logstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"sentinela/internal/logs"
)

type Config struct {
	URL           string // http://clickhouse:8123
	Database      string
	User          string
	Password      string
	RetentionDays int
	Timeout       time.Duration
}

type Store struct {
	cfg   Config
	hc    *http.Client
	ready atomic.Bool
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func New(cfg Config) (*Store, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("CLICKHOUSE_URL inválida (use http://host:8123)")
	}
	if cfg.Database == "" {
		cfg.Database = "sentinela"
	}
	if !identRe.MatchString(cfg.Database) { // o nome do banco entra no SQL: só identificador simples
		return nil, errors.New("CLICKHOUSE_DB inválido (use letras, números e _)")
	}
	if cfg.RetentionDays < 1 {
		cfg.RetentionDays = 90
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Store{cfg: cfg, hc: &http.Client{Timeout: cfg.Timeout}}, nil
}

// Ready informa se o esquema foi criado (a API sobe mesmo com o ClickHouse fora do ar).
func (s *Store) Ready() bool { return s != nil && s.ready.Load() }

func (s *Store) table() string { return s.cfg.Database + ".logs" }

const schemaTable = `CREATE TABLE IF NOT EXISTS %s (
	ts        DateTime64(3, 'UTC'),
	server_id UUID,
	source    LowCardinality(String),
	type      LowCardinality(String),
	severity  LowCardinality(String),
	ip        String,
	port      UInt16,
	status    UInt16,
	fields    Map(String, String),
	raw       String CODEC(ZSTD(3)),
	INDEX idx_ip ip TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (server_id, source, ts)
TTL toDateTime(ts) + INTERVAL %d DAY
SETTINGS non_replicated_deduplication_window = 1000`

// Init cria banco e tabela (idempotente) e ajusta o TTL à retenção configurada.
func (s *Store) Init(ctx context.Context) error {
	if err := s.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+s.cfg.Database, nil); err != nil {
		return err
	}
	if err := s.exec(ctx, fmt.Sprintf(schemaTable, s.table(), s.cfg.RetentionDays), nil); err != nil {
		return err
	}
	ttl := fmt.Sprintf("ALTER TABLE %s MODIFY TTL toDateTime(ts) + INTERVAL %d DAY", s.table(), s.cfg.RetentionDays)
	if err := s.exec(ctx, ttl, nil); err != nil {
		return err
	}
	if err := s.initSystem(ctx); err != nil {
		return err
	}
	if err := s.initProcs(ctx); err != nil {
		return err
	}
	s.ready.Store(true)
	return nil
}

// Insert grava o lote. batchID vira o token de deduplicação: reenviar o mesmo lote não duplica linhas.
func (s *Store) Insert(ctx context.Context, serverID, batchID string, entries []logs.Entry) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	type row struct {
		TS       string            `json:"ts"`
		ServerID string            `json:"server_id"`
		Source   string            `json:"source"`
		Type     string            `json:"type"`
		Severity string            `json:"severity"`
		IP       string            `json:"ip"`
		Port     int               `json:"port"`
		Status   int               `json:"status"`
		Fields   map[string]string `json:"fields"`
		Raw      string            `json:"raw"`
	}
	for _, e := range entries {
		f := e.Fields
		if f == nil {
			f = map[string]string{}
		}
		if err := enc.Encode(row{e.Time.UTC().Format("2006-01-02 15:04:05.000"), serverID, e.Source, e.Type,
			e.Severity, e.IP, e.Port, e.Status, f, e.Raw}); err != nil {
			return err
		}
	}
	q := url.Values{}
	q.Set("query", "INSERT INTO "+s.table()+" FORMAT JSONEachRow")
	q.Set("insert_deduplication_token", serverID+":"+batchID)
	q.Set("date_time_input_format", "best_effort")
	asyncInsert(q)
	_, err := s.do(ctx, q, &buf)
	return err
}

// asyncInsert pede ao ClickHouse que agrupe inserts pequenos e concorrentes em uma única parte.
// wait_for_async_insert mantém a resposta só após a gravação (sem perda silenciosa) e
// async_insert_deduplicate preserva a deduplicação por insert_deduplication_token.
func asyncInsert(q url.Values) {
	q.Set("async_insert", "1")
	q.Set("wait_for_async_insert", "1")
	q.Set("async_insert_deduplicate", "1")
}

// Ping verifica a conectividade.
func (s *Store) Ping(ctx context.Context) error {
	return s.exec(ctx, "SELECT 1", nil)
}

func (s *Store) exec(ctx context.Context, sql string, params map[string]string) error {
	_, err := s.query(ctx, sql, params)
	return err
}

// query executa SQL (no corpo) com parâmetros tipados e devolve a resposta crua.
func (s *Store) query(ctx context.Context, sql string, params map[string]string) ([]byte, error) {
	q := url.Values{}
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	q.Set("output_format_json_quote_64bit_integers", "0")
	return s.do(ctx, q, strings.NewReader(sql))
}

func (s *Store) do(ctx context.Context, q url.Values, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL+"/?"+q.Encode(), body)
	if err != nil {
		return nil, err
	}
	if s.cfg.User != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.User)
		req.Header.Set("X-ClickHouse-Key", s.cfg.Password)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("clickhouse: HTTP %d: %s", resp.StatusCode, msg)
	}
	return raw, nil
}
