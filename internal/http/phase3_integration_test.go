//go:build integration

package http_test

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"sentinela/internal/metrics"
)

func i64p(v int64) *int64 { return &v }

// sample insere uma amostra diretamente (controle exato de tempo e contadores).
func (e *env) sample(serverID string, at time.Time, cpu float64, ncpu int, memUsed, memTotal int64, rx, tx *int64) {
	e.t.Helper()
	_, err := e.pool.Exec(context.Background(), `INSERT INTO server_metrics
		(server_id, collected_at, received_at, cpu_usage_percent, cpu_count, load_average_1m,
		 memory_total_bytes, memory_used_bytes, memory_available_bytes, network_rx_bytes_total, network_tx_bytes_total)
		VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		serverID, at, cpu, ncpu, cpu/100, memTotal, memUsed, memTotal-memUsed, rx, tx)
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func (e *env) queryID(q string, args ...any) string {
	e.t.Helper()
	var id string
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&id); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return id
}

func fnum(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func near(a any, want float64) bool {
	f, ok := a.(float64)
	return ok && math.Abs(f-want) < 1e-6
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func TestPhase3EndpointsRequireAdminKey(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	for _, p := range []string{
		"/api/v1/servers/" + id + "/summary", "/api/v1/servers/" + id + "/metrics",
		"/api/v1/dashboard/summary", "/api/v1/dashboard/metrics",
		"/api/v1/dashboard/recent-alerts", "/api/v1/dashboard/recent-incidents",
	} {
		if r := e.do("GET", p, "", nil); r.Status != 401 {
			t.Errorf("%s sem chave: %d", p, r.Status)
		}
		_, tok := e.issue(id, nil)
		if r := e.do("GET", p, tok, nil); r.Status != 401 {
			t.Errorf("%s com token de agente: %d", p, r.Status)
		}
	}
}

func TestServerMetricsRawRatesMatchGoImplementation(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	base := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)

	type s struct {
		at     time.Time
		rx, tx int64
	}
	series := []s{
		{base, 1000, 500},
		{base.Add(15 * time.Second), 4000, 1500},
		{base.Add(30 * time.Second), 100, 100},   // reset de contador
		{base.Add(45 * time.Second), 1600, 400},  // volta a ser válido
		{base.Add(60 * time.Second), 1600, 400},  // tráfego zero
		{base.Add(16 * time.Minute), 9999, 9999}, // lacuna > 10 min
	}
	var net []metrics.NetSample
	for _, p := range series {
		e.sample(id, p.at, 20, 4, 250, 1000, i64p(p.rx), i64p(p.tx))
		net = append(net, metrics.NetSample{At: p.at, RX: p.rx, TX: p.tx})
	}
	want := map[time.Time]metrics.Rate{}
	for _, r := range metrics.Rates(net) {
		want[r.At] = r
	}
	if len(want) != 3 {
		t.Fatalf("premissa do teste: esperava 3 taxas válidas em Go, obteve %d", len(want))
	}

	r := e.admin("GET", "/api/v1/servers/"+id+"/metrics?interval=raw&from="+ts(base.Add(-time.Minute))+"&to="+ts(time.Now()), nil)
	if r.Status != 200 || len(r.list()) != len(series) || r.meta()["interval"] != "raw" || r.meta()["bucket_seconds"] != float64(0) {
		t.Fatalf("raw: %d %s", r.Status, r.Raw)
	}
	for i, raw := range r.list() {
		pt := raw.(map[string]any)
		at, _ := time.Parse(time.RFC3339Nano, pt["t"].(string))
		if !at.Equal(series[i].at) {
			t.Fatalf("ponto %d fora de ordem: %v", i, at)
		}
		rx := fnum(pt, "network_rx_bytes_per_sec", "avg")
		tx := fnum(pt, "network_tx_bytes_per_sec", "avg")
		if exp, ok := want[series[i].at]; ok {
			if !near(rx, exp.RXBytesPerSec) || !near(tx, exp.TXBytesPerSec) {
				t.Errorf("ponto %d: taxa SQL (%v, %v) difere da implementação Go (%v, %v)", i, rx, tx, exp.RXBytesPerSec, exp.TXBytesPerSec)
			}
		} else if rx != nil || tx != nil {
			t.Errorf("ponto %d: taxa deveria ser nula (primeira amostra, reset ou lacuna): %v %v", i, rx, tx)
		}
		if !near(fnum(pt, "memory_used_percent", "avg"), 25) || fnum(pt, "swap_used_percent", "avg") != nil {
			t.Errorf("ponto %d: memória/swap: %v", i, pt)
		}
		// em amostras originais min = avg = max
		if fnum(pt, "cpu_usage_percent", "min") != fnum(pt, "cpu_usage_percent", "max") {
			t.Errorf("ponto %d: raw deveria ter min = max", i)
		}
	}
}

func TestServerMetricsAggregation(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	base := time.Unix((time.Now().Unix()/300)*300, 0).UTC().Add(-2 * time.Hour) // alinhado a 5 min
	for i := 0; i < 60; i++ {
		e.sample(id, base.Add(time.Duration(i)*time.Minute), float64(i), 2, 100, 1000, nil, nil)
	}
	r := e.admin("GET", "/api/v1/servers/"+id+"/metrics?interval=5m&from="+ts(base)+"&to="+ts(base.Add(time.Hour)), nil)
	if r.Status != 200 || len(r.list()) != 12 || r.meta()["interval"] != "5m" || r.meta()["bucket_seconds"] != float64(300) {
		t.Fatalf("agregação: %d %s", r.Status, r.Raw)
	}
	for k, raw := range r.list() {
		pt := raw.(map[string]any)
		at, _ := time.Parse(time.RFC3339Nano, pt["t"].(string))
		if !at.Equal(base.Add(time.Duration(k) * 5 * time.Minute)) {
			t.Errorf("balde %d começa em %v", k, at)
		}
		if pt["samples"] != float64(5) ||
			!near(fnum(pt, "cpu_usage_percent", "min"), float64(5*k)) ||
			!near(fnum(pt, "cpu_usage_percent", "avg"), float64(5*k+2)) ||
			!near(fnum(pt, "cpu_usage_percent", "max"), float64(5*k+4)) {
			t.Errorf("balde %d: %v", k, pt)
		}
		if fnum(pt, "network_rx_bytes_per_sec", "avg") != nil {
			t.Errorf("sem contadores de rede a taxa deve ser nula")
		}
	}
	// baldes sem dados são omitidos: período vazio devolve lista vazia (não null)
	r = e.admin("GET", "/api/v1/servers/"+id+"/metrics?from="+ts(base.Add(-48*time.Hour))+"&to="+ts(base.Add(-47*time.Hour)), nil)
	if r.Status != 200 || r.list() == nil || len(r.list()) != 0 {
		t.Errorf("período vazio: %d %s", r.Status, r.Raw)
	}
}

func TestServerMetricsAutoIntervalAndValidation(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	now := time.Now().UTC()
	get := func(q string) resp { return e.admin("GET", "/api/v1/servers/"+id+"/metrics?"+q, nil) }

	for _, c := range []struct{ q, want string }{
		{"", "raw"},
		{"from=" + ts(now.Add(-7*24*time.Hour)), "15m"},
		{"from=" + ts(now.Add(-30*24*time.Hour)), "1h"},
		{"from=" + ts(now.Add(-90*24*time.Hour+time.Hour)), "6h"},
	} {
		if r := get(c.q); r.Status != 200 || r.meta()["interval"] != c.want {
			t.Errorf("%q: %d %s", c.q, r.Status, r.Raw)
		}
	}
	bad := []string{
		"from=ontem", "to=amanha", "interval=2m", "interval=raw&from=" + ts(now.Add(-3*time.Hour)),
		"from=" + ts(now.Add(-91*24*time.Hour)), "from=" + ts(now) + "&to=" + ts(now.Add(-time.Hour)),
		"interval=1m&from=" + ts(now.Add(-30*24*time.Hour)),
	}
	for _, q := range bad {
		if r := get(q); r.Status != 422 || r.errCode() != "VALIDATION_ERROR" {
			t.Errorf("%q deveria ser 422: %d %s", q, r.Status, r.Raw)
		}
	}
	if r := e.admin("GET", "/api/v1/servers/nao-uuid/metrics", nil); r.Status != 400 {
		t.Errorf("id inválido: %d", r.Status)
	}
	if r := e.admin("GET", "/api/v1/servers/00000000-0000-0000-0000-000000000000/metrics", nil); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}

	// 'raw' denso demais é rejeitado em vez de truncado silenciosamente
	e.exec(`INSERT INTO server_metrics (server_id, collected_at, received_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes)
		SELECT $1, now() - g * interval '2 seconds', now(), 1, 10, 5, 5 FROM generate_series(1, 1100) g`, id)
	r := get("interval=raw&from=" + ts(now.Add(-50*time.Minute)))
	if r.Status != 422 || !strings.Contains(r.Raw, "interval") {
		t.Errorf("raw denso: %d %s", r.Status, r.Raw)
	}
	// o mesmo período agregado funciona e respeita o teto de pontos
	r = get("interval=1m&from=" + ts(now.Add(-50*time.Minute)))
	if r.Status != 200 || len(r.list()) == 0 || len(r.list()) > metrics.MaxPoints {
		t.Errorf("agregado: %d", r.Status)
	}
	// servidor excluído: 404
	e.admin("DELETE", "/api/v1/servers/"+id, nil)
	if r := get(""); r.Status != 404 {
		t.Errorf("servidor excluído: %d", r.Status)
	}
}

func TestServerSummary(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")

	// sem dados
	r := e.admin("GET", "/api/v1/servers/"+id+"/summary", nil)
	if r.Status != 200 || r.data()["latest"] != nil || r.data()["availability"].(map[string]any)["percent"] != nil {
		t.Fatalf("sem amostras: %d %s", r.Status, r.Raw)
	}

	e.exec(`UPDATE servers SET created_at = now() - interval '2 hours', last_seen_at = now() WHERE id = $1`, id)
	// 40 amostras a cada 15s; contadores crescem 1500 B / 15 s = 100 B/s
	e.exec(`INSERT INTO server_metrics (server_id, collected_at, received_at, cpu_usage_percent, cpu_count, load_average_1m,
			memory_total_bytes, memory_used_bytes, memory_available_bytes, swap_total_bytes, swap_used_bytes,
			network_rx_bytes_total, network_tx_bytes_total, uptime_seconds)
		SELECT $1, now() - g * interval '15 seconds', now() - g * interval '15 seconds', 42, 4, 0.5,
			1000, 400, 600, 100, 10, (40 - g) * 1500, (40 - g) * 3000, 5000
		FROM generate_series(0, 39) g`, id)
	e.exec(`INSERT INTO server_disks (server_id, mount_point, filesystem, total_bytes, used_bytes, available_bytes, collected_at)
		VALUES ($1, '/', 'ext4', 1000, 250, 750, now())`, id)
	rule := e.queryID(`INSERT INTO alert_rules (name, metric_name, operator, threshold, severity) VALUES ('cpu','cpu_usage_percent','>',90,'critical') RETURNING id`)
	rule2 := e.queryID(`INSERT INTO alert_rules (name, metric_name, operator, threshold, severity) VALUES ('mem','memory_used_percent','>',90,'warning') RETURNING id`)
	e.exec(`INSERT INTO alerts (rule_id, server_id, severity, status, message) VALUES ($1,$3,'critical','firing','x'), ($2,$3,'warning','acknowledged','y')`, rule, rule2, id)
	e.exec(`INSERT INTO alerts (rule_id, server_id, severity, status, message, resolved_at) VALUES ($1,$2,'info','resolved','z', now())`, rule, id)
	e.exec(`INSERT INTO incidents (server_id, rule_id, title, severity) VALUES ($1,$2,'CPU alta','critical')`, id, rule)
	e.exec(`INSERT INTO monitored_services (server_id, name, service_type, target, status) VALUES
		($1,'nginx','systemd','nginx','up'), ($1,'api','http','http://x','down'), ($1,'db','tcp','x:5432','unknown')`, id)

	r = e.admin("GET", "/api/v1/servers/"+id+"/summary", nil)
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Raw)
	}
	d := r.data()
	checks := map[string]bool{
		"servidor online":      fnum(d, "server", "connection_status") == "online",
		"cpu":                  near(fnum(d, "latest", "cpu_usage_percent"), 42),
		"mem %":                near(fnum(d, "latest", "memory", "used_percent"), 40),
		"swap usada":           fnum(d, "latest", "memory", "swap_used_bytes") == float64(10),
		"uptime":               fnum(d, "latest", "uptime_seconds") == float64(5000),
		"taxa rx (100 B/s)":    near(fnum(d, "latest", "network", "rx_bytes_per_sec"), 100),
		"taxa tx (200 B/s)":    near(fnum(d, "latest", "network", "tx_bytes_per_sec"), 200),
		"alertas ativos":       fnum(d, "alerts", "active") == float64(2),
		"críticos":             fnum(d, "alerts", "critical") == float64(1),
		"warnings":             fnum(d, "alerts", "warning") == float64(1),
		"info resolvido fora":  fnum(d, "alerts", "info") == float64(0),
		"incidentes abertos":   fnum(d, "incidents", "open") == float64(1),
		"serviços total":       fnum(d, "services", "total") == float64(3),
		"serviços up/down/unk": fnum(d, "services", "up") == float64(1) && fnum(d, "services", "down") == float64(1) && fnum(d, "services", "unknown") == float64(1),
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("falhou: %s\n%s", name, r.Raw)
		}
	}
	disks := d["disks"].([]any)
	if len(disks) != 1 || !near(disks[0].(map[string]any)["used_percent"], 25) {
		t.Errorf("discos: %v", disks)
	}
	// disponibilidade: ~585 s cobertos de uma janela de ~7200 s (desde o cadastro) ≈ 8,1%
	av, _ := fnum(d, "availability", "percent").(float64)
	ws, _ := fnum(d, "availability", "window_seconds").(float64)
	if av < 7.5 || av > 9 || math.Abs(ws-7200) > 5 {
		t.Errorf("disponibilidade: %v\n%s", fnum(d, "availability"), r.Raw)
	}

	// reset de contador na última amostra => taxa nula (não negativa)
	e.exec(`INSERT INTO server_metrics (server_id, collected_at, received_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes, network_rx_bytes_total, network_tx_bytes_total)
		VALUES ($1, now() + interval '15 seconds', now(), 1, 10, 5, 5, 10, 10)`, id)
	r = e.admin("GET", "/api/v1/servers/"+id+"/summary", nil)
	if r.data()["latest"].(map[string]any)["network"] != nil {
		t.Errorf("reset deveria zerar a taxa: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/servers/00000000-0000-0000-0000-000000000000/summary", nil); r.Status != 404 {
		t.Errorf("inexistente: %d", r.Status)
	}
}

func TestDashboardSummaryAggregatesCorrectly(t *testing.T) {
	e := newEnv(t, adminKey)

	// estado vazio
	r := e.admin("GET", "/api/v1/dashboard/summary", nil)
	if r.Status != 200 || fnum(r.data(), "servers", "total") != float64(0) ||
		fnum(r.data(), "resources", "memory", "used_percent") != nil ||
		fnum(r.data(), "resources", "cpu", "top_server") != nil || r.data()["data_as_of"] != nil {
		t.Fatalf("vazio: %d %s", r.Status, r.Raw)
	}

	a, b, c, _ := e.createServer("a-online"), e.createServer("b-online"), e.createServer("c-offline"), e.createServer("d-unknown")
	now := time.Now().UTC()
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id IN ($1,$2)`, a, b)
	e.exec(`UPDATE servers SET last_seen_at = now() - interval '10 minutes' WHERE id = $1`, c)
	e.admin("PATCH", "/api/v1/servers/"+b, map[string]string{"status": "maintenance"})

	// A: 90% CPU, 4 CPUs, mem 800/1000 | B: 10% CPU, 1 CPU, mem 300/3000 | C (offline): números altos que NÃO podem contar
	e.sample(a, now.Add(-time.Second), 90, 4, 800, 1000, nil, nil)
	e.sample(b, now.Add(-time.Second), 10, 1, 300, 3000, nil, nil)
	e.sample(c, now.Add(-10*time.Minute), 99, 64, 9000, 10000, nil, nil)
	e.exec(`INSERT INTO server_disks (server_id, mount_point, total_bytes, used_bytes, available_bytes, collected_at) VALUES
		($1,'/',1000,500,500,now()), ($2,'/',3000,300,2700,now()), ($3,'/',100000,99000,1000,now())`, a, b, c)

	rule := e.queryID(`INSERT INTO alert_rules (name, metric_name, operator, threshold, severity) VALUES ('r1','cpu_usage_percent','>',90,'critical') RETURNING id`)
	rule2 := e.queryID(`INSERT INTO alert_rules (name, metric_name, operator, threshold, severity) VALUES ('r2','memory_used_percent','>',90,'warning') RETURNING id`)
	e.exec(`INSERT INTO alerts (rule_id, server_id, severity, status, message) VALUES ($1,$3,'critical','firing','x'), ($2,$3,'warning','acknowledged','y')`, rule, rule2, a)
	e.exec(`INSERT INTO alerts (rule_id, server_id, severity, status, message, resolved_at) VALUES ($1,$2,'critical','resolved','z', now())`, rule, b)
	e.exec(`INSERT INTO incidents (server_id, rule_id, title, severity) VALUES ($1,$2,'CPU alta','critical')`, a, rule)

	r = e.admin("GET", "/api/v1/dashboard/summary", nil)
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Raw)
	}
	d := r.data()
	checks := map[string]bool{
		"total":          fnum(d, "servers", "total") == float64(4),
		"online":         fnum(d, "servers", "online") == float64(2),
		"offline":        fnum(d, "servers", "offline") == float64(1),
		"unknown":        fnum(d, "servers", "unknown") == float64(1),
		"manutenção":     fnum(d, "servers", "maintenance") == float64(1),
		"com alertas":    fnum(d, "servers", "with_active_alerts") == float64(1),
		"alertas ativos": fnum(d, "alerts", "active") == float64(2) && fnum(d, "alerts", "critical") == float64(1) && fnum(d, "alerts", "warning") == float64(1),
		"incidentes":     fnum(d, "incidents", "open") == float64(1),
		"reportando":     fnum(d, "resources", "reporting_servers") == float64(2),
		// (90*4 + 10*1) / 5 = 74: ponderada por CPUs lógicas, offline excluído
		"cpu ponderada": near(fnum(d, "resources", "cpu", "weighted_avg_percent"), 74),
		"cpu máx":       near(fnum(d, "resources", "cpu", "max_percent"), 90),
		"top servidor":  fnum(d, "resources", "cpu", "top_server", "id") == a && fnum(d, "resources", "cpu", "top_server", "name") == "a-online",
		"distribuição":  fnum(d, "resources", "cpu", "distribution", "low") == float64(1) && fnum(d, "resources", "cpu", "distribution", "high") == float64(1) && fnum(d, "resources", "cpu", "distribution", "medium") == float64(0),
		// Σusado/Σtotal = 1100/4000 = 27,5%  (a média simples de 80% e 10% daria 45%)
		"memória Σ/Σ": near(fnum(d, "resources", "memory", "used_percent"), 27.5) && fnum(d, "resources", "memory", "used_bytes") == float64(1100) && fnum(d, "resources", "memory", "total_bytes") == float64(4000),
		// disco: (500+300)/(1000+3000) = 20%; o disco do servidor offline não entra
		"disco Σ/Σ":  near(fnum(d, "resources", "disk", "used_percent"), 20),
		"data_as_of": d["data_as_of"] != nil,
		"updated_at": d["updated_at"] != nil,
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("falhou: %s\n%s", name, r.Raw)
		}
	}
	// servidor excluído sai de todos os agregados
	e.admin("DELETE", "/api/v1/servers/"+a, nil)
	r = e.admin("GET", "/api/v1/dashboard/summary", nil)
	if fnum(r.data(), "servers", "total") != float64(3) || fnum(r.data(), "servers", "with_active_alerts") != float64(0) ||
		fnum(r.data(), "alerts", "active") != float64(0) || fnum(r.data(), "incidents", "open") != float64(0) ||
		!near(fnum(r.data(), "resources", "cpu", "weighted_avg_percent"), 10) {
		t.Errorf("após excluir A (alertas/incidentes de servidor removido não contam): %s", r.Raw)
	}
}

func TestDashboardMetrics(t *testing.T) {
	e := newEnv(t, adminKey)
	a, b := e.createServer("a"), e.createServer("b")
	base := time.Unix((time.Now().Unix()/300)*300, 0).UTC().Add(-3 * time.Hour)
	for i := 0; i < 10; i++ {
		at := base.Add(time.Duration(i) * 30 * time.Second) // 10 amostras por servidor no mesmo balde de 5 min
		e.sample(a, at, 20, 2, 800, 1000, nil, nil)
		e.sample(b, at, 40, 2, 300, 3000, nil, nil)
	}
	from, to := ts(base), ts(base.Add(time.Hour))

	r := e.admin("GET", "/api/v1/dashboard/metrics?interval=5m&from="+from+"&to="+to, nil)
	if r.Status != 200 || len(r.list()) != 1 {
		t.Fatalf("todos: %d %s", r.Status, r.Raw)
	}
	pt := r.list()[0].(map[string]any)
	if pt["servers"] != float64(2) || pt["samples"] != float64(20) ||
		!near(fnum(pt, "cpu_usage_percent", "avg"), 30) || !near(fnum(pt, "cpu_usage_percent", "max"), 40) ||
		!near(pt["memory_used_percent"], 27.5) { // 11000/40000, não a média de 80% e 10%
		t.Errorf("agregado: %v", pt)
	}

	r = e.admin("GET", "/api/v1/dashboard/metrics?interval=5m&from="+from+"&to="+to+"&server_id="+b, nil)
	pt = r.list()[0].(map[string]any)
	if pt["servers"] != float64(1) || !near(fnum(pt, "cpu_usage_percent", "avg"), 40) || !near(pt["memory_used_percent"], 10) {
		t.Errorf("filtro por servidor: %v", pt)
	}
	// vários ids (repetidos e separados por vírgula)
	r = e.admin("GET", "/api/v1/dashboard/metrics?interval=5m&from="+from+"&to="+to+"&server_id="+a+","+b, nil)
	if len(r.list()) != 1 || r.list()[0].(map[string]any)["servers"] != float64(2) {
		t.Errorf("vários ids: %s", r.Raw)
	}
	// intervalo automático nunca é 'raw' no dashboard
	if r := e.admin("GET", "/api/v1/dashboard/metrics", nil); r.Status != 200 || r.meta()["interval"] != "1m" {
		t.Errorf("auto: %d %s", r.Status, r.Raw)
	}
	for _, q := range []string{"interval=raw", "server_id=xyz", "interval=3m", "server_id=" + strings.Repeat(a+",", 51)} {
		if r := e.admin("GET", "/api/v1/dashboard/metrics?"+q, nil); r.Status != 422 {
			t.Errorf("%q deveria ser 422: %d", q, r.Status)
		}
	}
	// servidor excluído não entra
	e.admin("DELETE", "/api/v1/servers/"+b, nil)
	r = e.admin("GET", "/api/v1/dashboard/metrics?interval=5m&from="+from+"&to="+to, nil)
	if pt := r.list()[0].(map[string]any); pt["servers"] != float64(1) || !near(fnum(pt, "cpu_usage_percent", "avg"), 20) {
		t.Errorf("após excluir B: %v", pt)
	}
}

func TestRecentAlertsAndIncidents(t *testing.T) {
	e := newEnv(t, adminKey)
	a := e.createServer("a")
	rules := make([]string, 4)
	for i := range rules {
		rules[i] = e.queryID(`INSERT INTO alert_rules (name, metric_name, operator, threshold, severity) VALUES ($1,'cpu_usage_percent','>',90,'critical') RETURNING id`, "regra-"+string(rune('a'+i)))
	}
	e.exec(`INSERT INTO alerts (rule_id, server_id, severity, status, message, triggered_at) VALUES
		($1,$4,'critical','firing','m1', now() - interval '4 hours'),
		($2,$4,'warning','acknowledged','m2', now() - interval '3 hours'),
		($3,$4,'info','firing','m3', now() - interval '1 hour')`, rules[0], rules[1], rules[2], a)
	e.exec(`INSERT INTO alerts (rule_id, server_id, severity, status, message, triggered_at, resolved_at) VALUES
		($1,$2,'critical','resolved','m4', now() - interval '2 hours', now() - interval '90 minutes')`, rules[3], a)

	r := e.admin("GET", "/api/v1/dashboard/recent-alerts", nil)
	if r.Status != 200 || len(r.list()) != 4 {
		t.Fatalf("todos: %d %s", r.Status, r.Raw)
	}
	first := r.list()[0].(map[string]any)
	if first["message"] != "m3" || first["server_name"] != "a" || first["rule_name"] != "regra-c" {
		t.Errorf("mais recente primeiro: %v", first)
	}
	if r := e.admin("GET", "/api/v1/dashboard/recent-alerts?limit=2", nil); len(r.list()) != 2 {
		t.Errorf("limit: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/dashboard/recent-alerts?status=active", nil); len(r.list()) != 3 {
		t.Errorf("active: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/dashboard/recent-alerts?status=resolved", nil); len(r.list()) != 1 {
		t.Errorf("resolved: %s", r.Raw)
	}
	for _, q := range []string{"limit=0", "limit=51", "limit=x", "status=bogus"} {
		if r := e.admin("GET", "/api/v1/dashboard/recent-alerts?"+q, nil); r.Status != 422 {
			t.Errorf("%q: %d", q, r.Status)
		}
	}

	e.exec(`INSERT INTO incidents (server_id, rule_id, title, severity, started_at) VALUES ($1,$2,'aberto','critical', now() - interval '2 hours')`, a, rules[0])
	e.exec(`INSERT INTO incidents (server_id, rule_id, title, severity, status, started_at, resolved_at) VALUES ($1,$2,'resolvido','warning','resolved', now() - interval '5 hours', now() - interval '4 hours')`, a, rules[1])
	r = e.admin("GET", "/api/v1/dashboard/recent-incidents", nil)
	if r.Status != 200 || len(r.list()) != 2 {
		t.Fatalf("incidentes: %d %s", r.Status, r.Raw)
	}
	open := r.list()[0].(map[string]any)
	dur, _ := open["duration_seconds"].(float64)
	if open["title"] != "aberto" || open["server_name"] != "a" || dur < 7195 || dur > 7260 {
		t.Errorf("incidente aberto (duração até agora ≈ 7200 s): %v", open)
	}
	closed := r.list()[1].(map[string]any)
	if closed["duration_seconds"] != float64(3600) {
		t.Errorf("incidente resolvido (3600 s): %v", closed)
	}
	if r := e.admin("GET", "/api/v1/dashboard/recent-incidents?status=open", nil); len(r.list()) != 1 {
		t.Errorf("status=open: %s", r.Raw)
	}
	if r := e.admin("GET", "/api/v1/dashboard/recent-incidents?status=x", nil); r.Status != 422 {
		t.Errorf("status inválido: %d", r.Status)
	}
}

func TestIngestionIsCountedInPrometheus(t *testing.T) {
	e := newEnv(t, adminKey)
	_, tok := e.issue(e.createServer("srv"), nil)
	ts0 := time.Now().Add(-3 * time.Second)
	e.do("POST", "/api/v1/agent/metrics", tok, payload(ts0))
	e.do("POST", "/api/v1/agent/metrics", tok, payload(ts0)) // duplicada
	r := e.do("GET", "/metrics", "", nil)
	if !strings.Contains(r.Raw, `sentinela_agent_samples_total{result="stored"} 1`) ||
		!strings.Contains(r.Raw, `sentinela_agent_samples_total{result="duplicate"} 1`) {
		t.Errorf("contadores de amostras ausentes:\n%s", grep(r.Raw, "agent_samples"))
	}
}

func grep(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
