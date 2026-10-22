package logstore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Filter restringe consultas. Campos vazios não filtram.
type Filter struct {
	ServerID string // UUID já validado pelo chamador
	Source   string
	Type     string
	Severity string
	IP       string
	Q        string // busca (sem diferenciar maiúsculas) no texto original
	From, To time.Time
}

func (f Filter) where() (string, map[string]string) {
	conds := []string{"ts >= fromUnixTimestamp64Milli({from:Int64})", "ts < fromUnixTimestamp64Milli({to:Int64})"}
	p := map[string]string{
		"from": strconv.FormatInt(f.From.UnixMilli(), 10),
		"to":   strconv.FormatInt(f.To.UnixMilli(), 10),
	}
	add := func(cond, name, val string) {
		if val != "" {
			conds = append(conds, cond)
			p[name] = val
		}
	}
	add("server_id = {server:UUID}", "server", f.ServerID)
	add("source = {source:String}", "source", f.Source)
	add("type = {type:String}", "type", f.Type)
	add("severity = {severity:String}", "severity", f.Severity)
	add("ip = {ip:String}", "ip", f.IP)
	add("positionCaseInsensitiveUTF8(raw, {q:String}) > 0", "q", f.Q)
	return strings.Join(conds, " AND "), p
}

// Row é uma linha devolvida pela consulta.
type Row struct {
	Time     time.Time         `json:"time"`
	ServerID string            `json:"server_id"`
	Source   string            `json:"source"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	IP       string            `json:"ip,omitempty"`
	Port     int               `json:"port,omitempty"`
	Status   int               `json:"status,omitempty"`
	Fields   map[string]string `json:"fields"`
	Raw      string            `json:"raw,omitempty"`
}

// List devolve uma página (mais recentes primeiro) e o total que atende ao filtro.
// Os resumos por minuto do nginx (access_summary) não são linhas de log: só aparecem se pedidos em Type.
func (s *Store) List(ctx context.Context, f Filter, page, perPage int) ([]Row, int, error) {
	where, p := f.where()
	if f.Type == "" {
		where += " AND type != 'access_summary'"
	}
	raw, err := s.query(ctx, "SELECT count() AS n FROM "+s.table()+" WHERE "+where+" FORMAT JSONEachRow", p)
	if err != nil {
		return nil, 0, err
	}
	var cnt struct {
		N int `json:"n"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &cnt); err != nil {
		return nil, 0, fmt.Errorf("clickhouse: resposta inválida: %w", err)
	}
	if cnt.N == 0 {
		return []Row{}, 0, nil
	}
	p["limit"], p["offset"] = strconv.Itoa(perPage), strconv.Itoa((page-1)*perPage)
	sql := `SELECT toUnixTimestamp64Milli(ts) AS ts_ms, toString(server_id) AS sid, source, type, severity,
		ip, port, status, fields, raw FROM ` + s.table() + ` WHERE ` + where +
		` ORDER BY ts DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32} FORMAT JSONEachRow`
	raw, err = s.query(ctx, sql, p)
	if err != nil {
		return nil, 0, err
	}
	rows := []Row{}
	err = eachRow(raw, func(line []byte) error {
		var r struct {
			Row
			TSMs int64  `json:"ts_ms"`
			SID  string `json:"sid"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		r.Row.Time, r.Row.ServerID = time.UnixMilli(r.TSMs).UTC(), r.SID
		rows = append(rows, r.Row)
		return nil
	})
	return rows, cnt.N, err
}

func eachRow(raw []byte, fn func([]byte) error) error {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		if err := fn(sc.Bytes()); err != nil {
			return fmt.Errorf("clickhouse: resposta inválida: %w", err)
		}
	}
	return sc.Err()
}

// Stats é o resumo para o painel.
type Stats struct {
	From         time.Time       `json:"from"`
	To           time.Time       `json:"to"`
	BucketSecond int             `json:"bucket_seconds"`
	BySource     []SourceCount   `json:"by_source"`
	TopIPs       []IPCount       `json:"top_ips"`
	TopPorts     []PortCount     `json:"top_blocked_ports"`
	Timeline     []TimelinePoint `json:"timeline"`
	Traffic      []TrafficPoint  `json:"traffic"`
}

type SourceCount struct {
	Source string `json:"source"`
	Type   string `json:"type"`
	Count  int64  `json:"count"`
}

type IPCount struct {
	IP         string `json:"ip"`
	Events     int64  `json:"events"`
	Bans       int64  `json:"bans"`
	Blocks     int64  `json:"firewall_blocks"`
	HTTPErrors int64  `json:"http_errors"`
}

type PortCount struct {
	Port   int   `json:"port"`
	Blocks int64 `json:"blocks"`
}

type TimelinePoint struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"`
	Count  int64     `json:"count"`
}

// TrafficPoint soma os resumos por minuto do nginx (volume total, não só o que foi gravado em detalhe).
type TrafficPoint struct {
	Time     time.Time `json:"time"`
	Requests int64     `json:"requests"`
	Errors4  int64     `json:"errors_4xx"`
	Errors5  int64     `json:"errors_5xx"`
}

func bucketFor(from, to time.Time) int {
	step := int(to.Sub(from).Seconds()) / 120 // até ~120 pontos
	step = (step + 59) / 60 * 60              // múltiplo de 1 min, no mínimo 1 min
	return max(step, 60)
}

// Stats agrega o período. O filtro Type/IP/Q também vale, mas o uso típico é só servidor e período.
func (s *Store) Stats(ctx context.Context, f Filter) (Stats, error) {
	where, p := f.where()
	step := bucketFor(f.From, f.To)
	p["step"] = strconv.Itoa(step)
	t := s.table()
	st := Stats{From: f.From.UTC(), To: f.To.UTC(), BucketSecond: step,
		BySource: []SourceCount{}, TopIPs: []IPCount{}, TopPorts: []PortCount{}, Timeline: []TimelinePoint{}, Traffic: []TrafficPoint{}}

	run := func(sql string, fn func([]byte) error) error {
		raw, err := s.query(ctx, sql+" FORMAT JSONEachRow", p)
		if err != nil {
			return err
		}
		return eachRow(raw, fn)
	}

	if err := run(`SELECT source, type, count() AS count FROM `+t+` WHERE `+where+
		` AND type != 'access_summary' GROUP BY source, type ORDER BY count DESC`, func(l []byte) error {
		var r SourceCount
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		st.BySource = append(st.BySource, r)
		return nil
	}); err != nil {
		return st, err
	}

	if err := run(`SELECT ip, count() AS events, countIf(type = 'ban') AS bans,
			countIf(source = 'firewall' AND type != 'allow') AS firewall_blocks,
			countIf(source = 'nginx' AND status >= 400) AS http_errors
		FROM `+t+` WHERE `+where+` AND ip != '' AND type NOT IN ('access_summary', 'unban', 'allow')
		GROUP BY ip ORDER BY events DESC LIMIT 10`, func(l []byte) error {
		var r IPCount
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		st.TopIPs = append(st.TopIPs, r)
		return nil
	}); err != nil {
		return st, err
	}

	if err := run(`SELECT port, count() AS blocks FROM `+t+` WHERE `+where+
		` AND source = 'firewall' AND type != 'allow' AND port > 0 GROUP BY port ORDER BY blocks DESC LIMIT 10`, func(l []byte) error {
		var r PortCount
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		st.TopPorts = append(st.TopPorts, r)
		return nil
	}); err != nil {
		return st, err
	}

	if err := run(`SELECT toUnixTimestamp(toStartOfInterval(toDateTime(ts), INTERVAL {step:UInt32} SECOND)) AS t, source, count() AS count
		FROM `+t+` WHERE `+where+` AND type != 'access_summary' GROUP BY t, source ORDER BY t`, func(l []byte) error {
		var r struct {
			T      int64  `json:"t"`
			Source string `json:"source"`
			Count  int64  `json:"count"`
		}
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		st.Timeline = append(st.Timeline, TimelinePoint{Time: time.Unix(r.T, 0).UTC(), Source: r.Source, Count: r.Count})
		return nil
	}); err != nil {
		return st, err
	}

	if err := run(`SELECT toUnixTimestamp(toStartOfInterval(toDateTime(ts), INTERVAL {step:UInt32} SECOND)) AS t,
			sum(toUInt64OrZero(fields['requests'])) AS requests,
			sum(toUInt64OrZero(fields['s4xx'])) AS errors_4xx, sum(toUInt64OrZero(fields['s5xx'])) AS errors_5xx
		FROM `+t+` WHERE `+where+` AND type = 'access_summary' GROUP BY t ORDER BY t`, func(l []byte) error {
		var r struct {
			T        int64 `json:"t"`
			Requests int64 `json:"requests"`
			E4       int64 `json:"errors_4xx"`
			E5       int64 `json:"errors_5xx"`
		}
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		st.Traffic = append(st.Traffic, TrafficPoint{Time: time.Unix(r.T, 0).UTC(), Requests: r.Requests, Errors4: r.E4, Errors5: r.E5})
		return nil
	}); err != nil {
		return st, err
	}
	return st, nil
}
