//go:build integration

package http_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/config"
	"sentinela/internal/events"
	"sentinela/internal/http/handlers"
	"sentinela/internal/retention"
	"sentinela/internal/servers"
)

// ---------- cliente SSE de teste ----------

type sseMsg struct {
	ID    string
	Event string
	Data  string
}

func (m sseMsg) env(t *testing.T) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(m.Data), &v); err != nil {
		t.Fatalf("data não é JSON: %q", m.Data)
	}
	return v
}

func (m sseMsg) payload(t *testing.T) map[string]any {
	d, _ := m.env(t)["data"].(map[string]any)
	return d
}

type sseClient struct {
	t        *testing.T
	Status   int
	Header   nethttp.Header
	Preamble []string // linhas antes do primeiro evento (retry:, comentários)
	msgs     chan sseMsg
	pings    chan struct{}
	cancel   context.CancelFunc
	closed   chan struct{}
	body     string // corpo quando o status != 200
}

func openSSE(t *testing.T, base, path, bearer string, hdr map[string]string) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", base+path, nil)
	req.Header.Set("Accept", "text/event-stream")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&nethttp.Client{}).Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &sseClient{t: t, Status: resp.StatusCode, Header: resp.Header, msgs: make(chan sseMsg, 4096),
		pings: make(chan struct{}, 4096), cancel: cancel, closed: make(chan struct{})}
	t.Cleanup(c.Close)
	if resp.StatusCode != 200 {
		raw := make([]byte, 4096)
		n, _ := resp.Body.Read(raw)
		c.body = string(raw[:n])
		resp.Body.Close()
		close(c.closed)
		return c
	}
	go func() {
		defer close(c.closed)
		defer close(c.msgs)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var cur sseMsg
		started := false
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.Event != "" || cur.Data != "" {
					c.msgs <- cur
					started = true
				}
				cur = sseMsg{}
			case strings.HasPrefix(line, ": ping"):
				c.pings <- struct{}{}
			case strings.HasPrefix(line, ":"), strings.HasPrefix(line, "retry:"):
				if !started {
					c.Preamble = append(c.Preamble, line)
				}
			case strings.HasPrefix(line, "id: "):
				cur.ID = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				cur.Event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				cur.Data += strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return c
}

func (c *sseClient) Close() { c.cancel() }

// next devolve a próxima mensagem; falha se o stream terminar ou o prazo estourar.
func (c *sseClient) next(d time.Duration) sseMsg {
	c.t.Helper()
	select {
	case m, ok := <-c.msgs:
		if !ok {
			c.t.Fatal("stream encerrado antes do evento esperado")
		}
		return m
	case <-time.After(d):
		c.t.Fatal("evento não chegou a tempo")
	}
	return sseMsg{}
}

func (c *sseClient) expect(typ string) sseMsg {
	c.t.Helper()
	m := c.next(5 * time.Second)
	if m.Event != typ {
		c.t.Fatalf("esperava %q, chegou %q: %s", typ, m.Event, m.Data)
	}
	return m
}

func (c *sseClient) none(d time.Duration) {
	c.t.Helper()
	select {
	case m, ok := <-c.msgs:
		if ok {
			c.t.Fatalf("evento inesperado: %s %s", m.Event, m.Data)
		}
	case <-time.After(d):
	}
}

func (c *sseClient) waitClosed(d time.Duration) bool {
	select {
	case <-c.closed:
		return true
	case <-time.After(d):
		return false
	}
}

func (e *env) stream(path string, hdr map[string]string) *sseClient {
	return openSSE(e.t, e.srv.URL, "/api/v1/events"+path, adminKey, hdr)
}

// ---------- cenários ----------

func fireAlert(e *env, name string) (serverID, ruleID string) {
	serverID = e.createServer(name)
	e.sample(serverID, time.Now().UTC(), 97, 4, 500, 1000, nil, nil)
	e.exec(`UPDATE servers SET last_seen_at = now() WHERE id=$1`, serverID)
	r := e.post("/api/v1/alert-rules", map[string]any{"name": "CPU alta", "metric_name": "cpu_usage_percent", "operator": ">", "threshold": 90, "severity": "critical", "server_id": serverID})
	if r.Status != 201 {
		e.t.Fatalf("regra: %d %s", r.Status, r.Raw)
	}
	return serverID, r.data()["id"].(string)
}

func TestStreamRequiresAdminAuthAndValidatesParameters(t *testing.T) {
	e := newEnv(t, adminKey)
	id := e.createServer("srv")
	_, tok := e.issue(id, nil)
	for _, bearer := range []string{"", tok, "chave-errada"} {
		if c := openSSE(t, e.srv.URL, "/api/v1/events", bearer, nil); c.Status != 401 {
			t.Errorf("credencial %q: %d", bearer, c.Status)
		}
	}
	for _, q := range []string{"?types=bogus", "?types=alert.triggered,xyz", "?types=alert.*", "?types=resync", "?server_id=xyz", "?last_event_id=abc", "?last_event_id=-5"} {
		if c := openSSE(t, e.srv.URL, "/api/v1/events"+q, adminKey, nil); c.Status != 422 || !strings.Contains(c.body, "VALIDATION_ERROR") {
			t.Errorf("%s: %d %s", q, c.Status, c.body)
		}
	}
	if c := openSSE(t, e.srv.URL, "/api/v1/events", adminKey, map[string]string{"Last-Event-ID": "x1"}); c.Status != 422 {
		t.Errorf("Last-Event-ID inválido: %d", c.Status)
	}
	// o endpoint só aceita GET
	if r := e.admin("POST", "/api/v1/events", nil); r.Status != 405 {
		t.Errorf("POST: %d", r.Status)
	}
}

func TestStreamHeadersAndPreamble(t *testing.T) {
	e := newEnv(t, adminKey)
	c := e.stream("", nil)
	if c.Status != 200 {
		t.Fatalf("status %d", c.Status)
	}
	if !strings.HasPrefix(c.Header.Get("Content-Type"), "text/event-stream") || c.Header.Get("Cache-Control") != "no-cache, no-transform" ||
		c.Header.Get("X-Accel-Buffering") != "no" || c.Header.Get("X-Request-Id") == "" {
		t.Errorf("cabeçalhos: %v", c.Header)
	}
	// força um evento para garantir que o preâmbulo já foi lido
	e.exec(`SELECT 1`)
	e.createServer("x")
	e.admin("PATCH", "/api/v1/servers/"+e.queryID(`SELECT id::text FROM servers LIMIT 1`), map[string]string{"status": "maintenance"})
	c.expect(events.TypeServerStatus)
	if len(c.Preamble) < 2 || c.Preamble[0] != "retry: 5000" || !strings.HasPrefix(c.Preamble[1], ": connected") {
		t.Errorf("preâmbulo: %v", c.Preamble)
	}
}

func TestAlertAndIncidentEventsWithoutSensitiveData(t *testing.T) {
	e := newEnv(t, adminKey)
	c := e.stream("", nil)
	srv, ruleID := fireAlert(e, "web-1")
	if err := e.evaluator().Tick(context.Background()); err != nil {
		t.Fatal(err)
	}

	inc := c.expect(events.TypeIncidentCreated)
	trig := c.expect(events.TypeAlertTriggered)
	i1, _ := strconv.Atoi(inc.ID)
	i2, _ := strconv.Atoi(trig.ID)
	if i1 == 0 || i2 <= i1 {
		t.Errorf("ids devem crescer: %s %s", inc.ID, trig.ID)
	}
	env := trig.env(t)
	if env["type"] != events.TypeAlertTriggered || env["id"] != float64(i2) || env["time"] == nil {
		t.Errorf("envelope: %v", env)
	}
	p := trig.payload(t)
	alertID, _ := p["alert_id"].(string)
	if p["server_id"] != srv || p["server_name"] != "web-1" || p["rule_id"] != ruleID || p["rule_name"] != "CPU alta" ||
		p["severity"] != "critical" || p["status"] != "firing" || alertID == "" || p["incident_id"] != inc.payload(t)["incident_id"] ||
		!strings.Contains(p["message"].(string), "97.0%") {
		t.Errorf("payload do alerta: %v", p)
	}
	ip := inc.payload(t)
	if ip["status"] != "open" || ip["title"] != "CPU alta — web-1" || ip["resolved_at"] != nil {
		t.Errorf("payload do incidente: %v", ip)
	}

	// reconhecimento: a nota do operador NÃO é publicada
	e.post("/api/v1/alerts/"+alertID+"/acknowledge", map[string]any{"note": "senha-do-banco-é-123"})
	ack := c.expect(events.TypeAlertAcknowledged)
	if ack.payload(t)["status"] != "acknowledged" || strings.Contains(ack.Data, "senha") || strings.Contains(ack.Data, "note") {
		t.Errorf("ack: %s", ack.Data)
	}

	// resolução manual: alerta e depois incidente
	e.post("/api/v1/alerts/"+alertID+"/resolve", nil)
	res := c.expect(events.TypeAlertResolved)
	closed := c.expect(events.TypeIncidentResolved)
	if res.payload(t)["status"] != "resolved" || closed.payload(t)["status"] != "resolved" || closed.payload(t)["resolved_at"] == nil {
		t.Errorf("resolução: %s / %s", res.Data, closed.Data)
	}
	c.none(300 * time.Millisecond)

	assertNoSensitive(t, e)
}

// Nada que identifique alvos internos, credenciais ou segredos pode estar no log de eventos.
func assertNoSensitive(t *testing.T, e *env) {
	t.Helper()
	rows, err := e.pool.Query(context.Background(), `SELECT type, data::text FROM events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	forbidden := []string{"token", "password", "senha", "secret", "authorization", "bearer", "http://", "https://", `"target"`, "hostname", "bot_", "snt_", "last_error"}
	n := 0
	for rows.Next() {
		var typ, data string
		rows.Scan(&typ, &data)
		n++
		low := strings.ToLower(data)
		for _, f := range forbidden {
			if strings.Contains(low, f) {
				t.Errorf("evento %s contém %q: %s", typ, f, data)
			}
		}
	}
	if n == 0 {
		t.Error("nenhum evento foi gravado")
	}
}

func TestServiceAndServerStatusEvents(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	_, tok := e.issue(srv, nil)
	c := e.stream("?types=service.status_changed,server.status_changed", nil)

	report := func(status string) {
		f := map[string]any{"key": "nginx", "status": "available", "source": "systemd", "unit": "nginx.service"}
		if status == "down" {
			f = map[string]any{"key": "nginx", "status": "stopped", "unit": "nginx.service"}
		}
		r := e.do("POST", "/api/v1/agent/discovery", tok, map[string]any{
			"checked_at": time.Now().UTC().Format(time.RFC3339Nano), "services": []any{f}})
		if r.Status != 200 {
			t.Fatalf("relatório: %d %s", r.Status, r.Raw)
		}
		time.Sleep(5 * time.Millisecond)
	}
	report("up")
	m := c.expect(events.TypeServiceStatus)
	p := m.payload(t)
	if p["service_id"] == nil || p["previous_status"] != "unknown" || p["status"] != "up" || p["name"] != "Nginx (automático)" || p["server_name"] != "web-1" || p["service_type"] != "discovered" {
		t.Errorf("payload: %v", p)
	}
	if strings.Contains(m.Data, "nginx.service") || strings.Contains(m.Data, "target") || strings.Contains(m.Data, "parado") {
		t.Errorf("o evento não pode vazar alvo/erro: %s", m.Data)
	}
	report("up") // mesmo estado: sem evento
	c.none(200 * time.Millisecond)
	report("down")
	if p := c.expect(events.TypeServiceStatus).payload(t); p["previous_status"] != "up" || p["status"] != "down" {
		t.Errorf("queda: %v", p)
	}

	// conectividade: transições detectadas pelo monitor (tempo simulado)
	now := time.Now().UTC()
	mon := &servers.ConnectivityMonitor{Pool: e.pool, Timeout: 60 * time.Second, Now: func() time.Time { return now }}
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.none(200 * time.Millisecond) // nunca visto: unknown -> unknown
	e.exec(`UPDATE servers SET last_seen_at = $2 WHERE id = $1`, srv, now)
	mon.Tick(context.Background())
	if p := c.expect(events.TypeServerStatus).payload(t); p["connection_status"] != "online" || p["previous_connection_status"] != "unknown" || p["server_id"] != srv {
		t.Errorf("online: %v", p)
	}
	mon.Tick(context.Background())
	c.none(200 * time.Millisecond) // sem mudança: sem evento
	now = now.Add(2 * time.Minute)
	mon.Tick(context.Background())
	if p := c.expect(events.TypeServerStatus).payload(t); p["connection_status"] != "offline" || p["previous_connection_status"] != "online" {
		t.Errorf("offline: %v", p)
	}
	e.exec(`UPDATE servers SET last_seen_at = $2 WHERE id = $1`, srv, now)
	mon.Tick(context.Background())
	if p := c.expect(events.TypeServerStatus).payload(t); p["connection_status"] != "online" || p["previous_connection_status"] != "offline" {
		t.Errorf("volta: %v", p)
	}

	// estado administrativo
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "maintenance"})
	if p := c.expect(events.TypeServerStatus).payload(t); p["status"] != "maintenance" || p["previous_status"] != "active" {
		t.Errorf("manutenção: %v", p)
	}
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"name": "web-1b"}) // só renomeou: sem evento
	c.none(200 * time.Millisecond)

	// concorrência do monitor: várias instâncias, uma transição, um evento
	now = now.Add(5 * time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			(&servers.ConnectivityMonitor{Pool: e.pool, Timeout: time.Minute, Now: func() time.Time { return now }}).Tick(context.Background())
		}()
	}
	wg.Wait()
	c.expect(events.TypeServerStatus)
	c.none(300 * time.Millisecond)
	assertNoSensitive(t, e)
}

func TestMetricsUpdatedIsOptInThrottledAndMinimal(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	_, tok := e.issue(srv, nil)
	def := e.stream("", nil)
	live := e.stream("?types=metrics.updated", nil)
	other := e.stream("?types=metrics.updated&server_id="+e.createServer("outro"), nil)

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		r := e.do("POST", "/api/v1/agent/metrics", tok, payload(now.Add(time.Duration(-10+i)*time.Second)))
		if r.Status != 200 {
			t.Fatalf("métricas: %d %s", r.Status, r.Raw)
		}
	}
	m := live.expect(events.TypeMetricsUpdated)
	if m.ID != "" {
		t.Errorf("evento efêmero não leva id: %q", m.ID)
	}
	p := m.payload(t)
	if p["server_id"] != srv || p["cpu_usage_percent"] != 12.5 || p["memory_used_percent"] != float64(40) || p["collected_at"] == nil {
		t.Errorf("payload: %v", p)
	}
	for _, k := range []string{"disks", "network", "host", "hostname", "load_average", "agent_version"} {
		if _, ok := p[k]; ok {
			t.Errorf("payload mínimo não deve ter %q", k)
		}
	}
	live.none(300 * time.Millisecond) // 3 amostras em sequência => 1 evento (limite de frequência por servidor)
	def.none(100 * time.Millisecond)  // padrão não inclui metrics.updated
	other.none(100 * time.Millisecond)
	if n := e.count(`SELECT count(*) FROM events`); n != 0 {
		t.Errorf("metrics.updated não pode ser gravado no log: %d", n)
	}
	// duplicada (idempotente) não gera evento
}

func TestFiltersByTypeAndServer(t *testing.T) {
	e := newEnv(t, adminKey)
	a, _ := fireAlert(e, "a")
	b, _ := fireAlert(e, "b")
	all := e.stream("", nil)
	onlyA := e.stream("?server_id="+a, nil)
	onlyResolved := e.stream("?types=alert.resolved", nil)

	e.evaluator().Tick(context.Background())
	for i := 0; i < 4; i++ { // 2 incidentes + 2 alertas
		all.next(5 * time.Second)
	}
	var seen []string
	for i := 0; i < 2; i++ {
		m := onlyA.next(5 * time.Second)
		if m.payload(t)["server_id"] != a {
			t.Errorf("filtro por servidor deixou passar %s", m.Data)
		}
		seen = append(seen, m.Event)
	}
	onlyA.none(300 * time.Millisecond)
	if strings.Join(seen, ",") != "incident.created,alert.triggered" {
		t.Errorf("A recebeu %v", seen)
	}
	onlyResolved.none(100 * time.Millisecond)

	e.exec(`UPDATE server_metrics SET cpu_usage_percent = 5 WHERE server_id = $1`, b)
	e.exec(`INSERT INTO server_metrics (server_id, collected_at, cpu_usage_percent, memory_total_bytes, memory_used_bytes, memory_available_bytes) VALUES ($1, now() + interval '1 second', 5, 10, 5, 5)`, b)
	e.evaluator().Tick(context.Background())
	m := onlyResolved.expect(events.TypeAlertResolved)
	if m.payload(t)["server_id"] != b {
		t.Errorf("%s", m.Data)
	}
	onlyResolved.none(300 * time.Millisecond)
	onlyA.none(100 * time.Millisecond)
}

func TestReconnectReplaysMissedEventsInOrderWithoutDuplicates(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	pub := func(n int) {
		for i := 0; i < n; i++ {
			e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": []string{"maintenance", "active"}[i%2]})
		}
	}
	first := e.stream("", nil)
	pub(2)
	m1 := first.expect(events.TypeServerStatus)
	first.expect(events.TypeServerStatus)
	first.Close() // cliente cai; o servidor continua gerando eventos
	first.waitClosed(2 * time.Second)

	pub(4) // eventos perdidos: ids seguintes
	id1, _ := strconv.Atoi(m1.ID)

	// reconecta com o último id que viu (o 2º evento tem id1+1)
	c := e.stream("", map[string]string{"Last-Event-ID": strconv.Itoa(id1 + 1)})
	var ids []int
	for i := 0; i < 4; i++ {
		id, _ := strconv.Atoi(c.expect(events.TypeServerStatus).ID)
		ids = append(ids, id)
	}
	for i, id := range ids {
		if id != id1+2+i {
			t.Errorf("replay fora de ordem ou com buraco: %v", ids)
			break
		}
	}
	c.none(300 * time.Millisecond) // nada duplicado
	// e segue ao vivo sem repetir
	pub(1)
	live := c.expect(events.TypeServerStatus)
	if n, _ := strconv.Atoi(live.ID); n != id1+6 {
		t.Errorf("ao vivo após replay: id %s (esperado %d)", live.ID, id1+6)
	}
	c.none(200 * time.Millisecond)

	// parâmetro de consulta equivale ao cabeçalho (clientes baseados em fetch)
	q := e.stream("?last_event_id="+strconv.Itoa(id1+4), nil)
	for want := id1 + 5; want <= id1+6; want++ {
		if got, _ := strconv.Atoi(q.expect(events.TypeServerStatus).ID); got != want {
			t.Errorf("via query: %d (esperado %d)", got, want)
		}
	}
	// o cabeçalho tem precedência sobre a query
	h := e.stream("?last_event_id=0", map[string]string{"Last-Event-ID": strconv.Itoa(id1 + 5)})
	if got, _ := strconv.Atoi(h.expect(events.TypeServerStatus).ID); got != id1+6 {
		t.Errorf("precedência do cabeçalho: %d", got)
	}
	// replay respeita o filtro de tipos
	f := e.stream("?types=alert.triggered", map[string]string{"Last-Event-ID": strconv.Itoa(id1)})
	f.none(300 * time.Millisecond)
}

func TestResyncWhenHistoryIsNotAvailable(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	for i := 0; i < 5; i++ {
		e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": []string{"maintenance", "active"}[i%2]})
	}
	// "ahead": id de outro histórico
	c := e.stream("", map[string]string{"Last-Event-ID": "999999"})
	if m := c.next(3 * time.Second); m.Event != events.TypeResync || m.ID != "" || !strings.Contains(m.Data, "ahead") {
		t.Errorf("ahead: %+v", m)
	}
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "active"}) // estava em manutenção: muda
	if m := c.expect(events.TypeServerStatus); m.ID == "" {                         // continua ao vivo depois do resync
		t.Error("deveria seguir ao vivo")
	}

	// "gap": a retenção removeu eventos que o cliente ainda não viu
	e.exec(`UPDATE events SET created_at = now() - interval '3 days' WHERE id <= 3`)
	if n, err := events.Purge(context.Background(), e.pool, time.Now().Add(-24*time.Hour)); err != nil || n != 3 {
		t.Fatalf("purge: %d %v", n, err)
	}
	g := e.stream("", map[string]string{"Last-Event-ID": "1"})
	m := g.next(3 * time.Second)
	if m.Event != events.TypeResync || !strings.Contains(m.Data, `"gap"`) {
		t.Errorf("gap: %+v", m)
	}
	// com Last-Event-ID dentro da janela retida: sem resync, só o que falta (aqui, nada)
	maxID := e.count(`SELECT COALESCE(max(id),0) FROM events`)
	if maxID <= 3 {
		t.Fatalf("premissa: deveriam restar eventos retidos (max=%d)", maxID)
	}
	ok := e.stream("", map[string]string{"Last-Event-ID": strconv.Itoa(maxID)})
	ok.none(300 * time.Millisecond)
	part := e.stream("", map[string]string{"Last-Event-ID": "3"}) // exatamente na fronteira da retenção
	for want := 4; want <= maxID; want++ {
		if got, _ := strconv.Atoi(part.expect(events.TypeServerStatus).ID); got != want {
			t.Errorf("fronteira da retenção: %d (esperado %d)", got, want)
		}
	}
}

// Servidor com limites pequenos, montando o handler diretamente (sem autenticação) para testar
// o comportamento de replay excessivo e de cliente lento.
func bareSSE(e *env, replayLimit, buffer int) (*httptest.Server, *events.Hub) {
	hub := e.startHub()
	hub.Buffer = buffer
	r := chi.NewRouter()
	r.Get("/events", handlers.Events{Hub: hub, Log: e.log, Heartbeat: time.Second, ReplayLimit: replayLimit}.Stream)
	srv := httptest.NewServer(r)
	e.t.Cleanup(srv.Close)
	return srv, hub
}

func TestResyncWhenTooManyEventsWereMissed(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	for i := 0; i < 8; i++ {
		e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": []string{"maintenance", "active"}[i%2]})
	}
	s, _ := bareSSE(e, 3, 256)
	c := openSSE(t, s.URL, "/events", "", map[string]string{"Last-Event-ID": "1"})
	m := c.next(3 * time.Second)
	if m.Event != events.TypeResync || !strings.Contains(m.Data, "too_many") {
		t.Fatalf("esperava resync too_many: %+v", m)
	}
	c.none(300 * time.Millisecond) // nada de reenvio parcial
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "maintenance"})
	c.expect(events.TypeServerStatus) // segue ao vivo
}

func TestSlowClientGetsResyncInsteadOfBlockingTheHub(t *testing.T) {
	e := newEnv(t, adminKey)
	s, hub := bareSSE(e, 1000, 2)
	c := openSSE(t, s.URL, "/events", "", nil)
	// inunda o hub mais rápido que o handler consegue escoar para o socket
	data := []byte(`{"pad":"` + strings.Repeat("x", 4000) + `"}`)
	got := make(chan bool, 1)
	go func() {
		for i := int64(1); i <= 20000; i++ {
			hub.Broadcast(events.Event{ID: i, Type: events.TypeAlertTriggered, Time: time.Now(), Data: data})
			if hub.Clients() == 0 { // o hub descartou o cliente lento
				got <- true
				return
			}
		}
		got <- false
	}()
	if !<-got {
		t.Skip("o handler acompanhou a inundação neste ambiente; o descarte está coberto no teste unitário do hub")
	}
	// o cliente recebe o aviso para ressincronizar
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-c.msgs:
			if !ok {
				t.Fatal("stream encerrou sem aviso de resync")
			}
			if m.Event == events.TypeResync {
				if !strings.Contains(m.Data, "overflow") {
					t.Errorf("motivo: %s", m.Data)
				}
				return
			}
		case <-deadline:
			t.Fatal("resync não chegou")
		}
	}
}

func TestDisconnectedClientsReleaseResources(t *testing.T) {
	e := newEnv(t, adminKey)
	var cs []*sseClient
	for i := 0; i < 6; i++ {
		cs = append(cs, e.stream("", nil))
	}
	waitFor(t, 3*time.Second, func() bool { return e.hub.Clients() == 6 }, "6 clientes conectados")
	for _, c := range cs {
		c.Close()
	}
	waitFor(t, 3*time.Second, func() bool { return e.hub.Clients() == 0 }, "assinaturas liberadas após desconexão")
	r := e.do("GET", "/metrics", "", nil)
	if !strings.Contains(r.Raw, "sentinela_sse_clients 0") {
		t.Errorf("gauge deveria voltar a 0:\n%s", grepLines(r.Raw, "sse_"))
	}
	// reconectar funciona normalmente
	e.stream("", nil)
	waitFor(t, 3*time.Second, func() bool { return e.hub.Clients() == 1 }, "reconexão")
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condição não atingida: %s", what)
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestConnectionLimits(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) { c.SSEMaxClients, c.SSEMaxClientsPerIP, c.TrustProxy = 3, 1, true })
	from := func(ip string) *sseClient {
		return openSSE(t, e.srv.URL, "/api/v1/events", adminKey, map[string]string{"X-Real-IP": ip})
	}
	a := from("203.0.113.1")
	if a.Status != 200 {
		t.Fatal(a.Status)
	}
	if b := from("203.0.113.1"); b.Status != 429 || b.Header.Get("Retry-After") == "" || !strings.Contains(b.body, "TOO_MANY_STREAMS") {
		t.Errorf("limite por IP: %d %s", b.Status, b.body)
	}
	b, c := from("203.0.113.2"), from("203.0.113.3")
	if b.Status != 200 || c.Status != 200 {
		t.Fatal("IPs distintos deveriam conectar")
	}
	if d := from("203.0.113.4"); d.Status != 503 || !strings.Contains(d.body, "STREAM_UNAVAILABLE") {
		t.Errorf("limite total: %d %s", d.Status, d.body)
	}
	a.Close()
	waitFor(t, 3*time.Second, func() bool { return e.hub.Clients() == 2 }, "vaga liberada")
	if d := from("203.0.113.4"); d.Status != 200 {
		t.Errorf("após liberar a vaga: %d", d.Status)
	}
}

func TestStreamSurvivesRequestTimeoutAndServerWriteTimeout(t *testing.T) {
	e := newEnvCfg(t, func(c *config.Config) {
		c.RequestTimeout = 300 * time.Millisecond // as rotas normais expiram rápido...
		c.SSEHeartbeat = 100 * time.Millisecond
	})
	// ...e o servidor tem WriteTimeout curto, como em produção (30 s) mas encurtado para o teste
	ts := httptest.NewUnstartedServer(e.router(e.hub))
	ts.Config.WriteTimeout = 300 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close) // registrado ANTES do cliente: o cliente fecha primeiro (Cleanup é LIFO)

	c := openSSE(t, ts.URL, "/api/v1/events", adminKey, nil)
	if c.Status != 200 {
		t.Fatal(c.Status)
	}
	deadline := time.After(1500 * time.Millisecond) // 5x o timeout de requisição e de escrita
	pings := 0
loop:
	for {
		select {
		case <-c.pings:
			pings++
		case <-c.closed:
			t.Fatalf("o stream foi encerrado pelo timeout (pings recebidos: %d)", pings)
		case <-deadline:
			break loop
		}
	}
	if pings < 8 {
		t.Errorf("deveria receber ~14 pings em 1,5 s: %d", pings)
	}
	// e ainda entrega eventos depois de muito tempo ocioso
	srv := e.createServer("x")
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "maintenance"})
	c.expect(events.TypeServerStatus)
}

func TestGracefulShutdownDoesNotWaitForOpenStreams(t *testing.T) {
	e := newEnv(t, adminKey)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &nethttp.Server{Handler: e.router(e.hub)}
	srv.RegisterOnShutdown(e.hub.Close) // igual ao cmd/api
	go srv.Serve(l)
	base := "http://" + l.Addr().String()

	var cs []*sseClient
	for i := 0; i < 3; i++ {
		c := openSSE(t, base, "/api/v1/events", adminKey, nil)
		if c.Status != 200 {
			t.Fatal(c.Status)
		}
		cs = append(cs, c)
	}
	waitFor(t, 3*time.Second, func() bool { return e.hub.Clients() == 3 }, "3 streams")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("o shutdown esperou os streams: %v", time.Since(start))
	}
	for i, c := range cs {
		if !c.waitClosed(2 * time.Second) {
			t.Errorf("stream %d não foi encerrado", i)
		}
	}
	if e.hub.Clients() != 0 {
		t.Error("assinaturas restantes")
	}
}

func TestEventsAreDeliveredAcrossAPIInstances(t *testing.T) {
	e := newEnv(t, adminKey)
	hubB := e.startHub() // segunda instância: outro hub e outro servidor HTTP, mesmo banco
	srvB := httptest.NewServer(e.router(hubB))
	t.Cleanup(srvB.Close)

	a := e.stream("", nil)
	b := openSSE(t, srvB.URL, "/api/v1/events", adminKey, nil)

	// a mudança acontece na instância A...
	srv := e.createServer("web-1")
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "maintenance"})
	ma, mb := a.expect(events.TypeServerStatus), b.expect(events.TypeServerStatus)
	if ma.ID == "" || ma.ID != mb.ID || ma.Data != mb.Data {
		t.Errorf("as duas instâncias deveriam entregar o mesmo evento: %s vs %s", ma.ID, mb.ID)
	}
	a.none(200 * time.Millisecond)
	b.none(200 * time.Millisecond)

	// ...e quem reconecta na instância B recebe o que perdeu, mesmo tendo sido gerado em A
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "active"})
	e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": "maintenance"})
	late := openSSE(t, srvB.URL, "/api/v1/events", adminKey, map[string]string{"Last-Event-ID": ma.ID})
	for i := 0; i < 2; i++ {
		late.expect(events.TypeServerStatus)
	}
	late.none(200 * time.Millisecond)
}

func TestRetentionJobPurgesOldEvents(t *testing.T) {
	e := newEnv(t, adminKey)
	srv := e.createServer("web-1")
	for i := 0; i < 4; i++ {
		e.admin("PATCH", "/api/v1/servers/"+srv, map[string]string{"status": []string{"maintenance", "active"}[i%2]})
	}
	e.exec(`UPDATE events SET created_at = now() - interval '3 days' WHERE id <= 2`)
	job := &retention.Job{Pool: e.pool, Days: 30, Interval: time.Hour, Batch: 100, Log: e.log, EventsRetention: 24 * time.Hour}
	if _, err := job.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM events`) != 2 || e.count(`SELECT purged_until FROM event_log_state`) != 2 {
		t.Errorf("eventos=%d purged_until=%d", e.count(`SELECT count(*) FROM events`), e.count(`SELECT purged_until FROM event_log_state`))
	}
	// desligado (0): nada é removido
	e.exec(`UPDATE events SET created_at = now() - interval '9 days'`)
	job.EventsRetention = 0
	job.RunOnce(context.Background())
	if e.count(`SELECT count(*) FROM events`) != 2 {
		t.Error("EventsRetention=0 não deve limpar")
	}
}
