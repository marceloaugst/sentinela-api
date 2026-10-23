//go:build integration

package logstore

import (
	"context"
	"os"
	"testing"
	"time"

	"sentinela/internal/logs"
	"sentinela/internal/procs"
	"sentinela/internal/sysmetrics"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("TEST_CLICKHOUSE_URL não definida")
	}
	s, err := New(Config{URL: url, Database: "sentinela_test", User: "default", Password: os.Getenv("TEST_CLICKHOUSE_PASSWORD"), RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.exec(ctx, "TRUNCATE TABLE "+s.table(), nil); err != nil {
		t.Fatal(err)
	}
	return s
}

const srvA, srvB = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"

func TestInsertListStats(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	batch := []logs.Entry{
		{Time: now.Add(-10 * time.Minute), Source: logs.SourceFail2ban, Type: logs.TypeBan, Severity: logs.SevWarning, IP: "203.0.113.9", Fields: map[string]string{"jail": "sshd"}, Raw: "Ban 203.0.113.9"},
		{Time: now.Add(-9 * time.Minute), Source: logs.SourceFirewall, Type: logs.TypeBlock, Severity: logs.SevWarning, IP: "203.0.113.9", Port: 22, Fields: map[string]string{"proto": "TCP"}, Raw: "[UFW BLOCK] SRC=203.0.113.9 DPT=22"},
		{Time: now.Add(-8 * time.Minute), Source: logs.SourceFirewall, Type: logs.TypeBlock, Severity: logs.SevWarning, IP: "198.51.100.7", Port: 3306, Raw: "[UFW BLOCK] DPT=3306"},
		{Time: now.Add(-7 * time.Minute), Source: logs.SourceNginx, Type: logs.TypeAccess, Severity: logs.SevWarning, IP: "198.51.100.7", Status: 404, Fields: map[string]string{"path": "/.env"}, Raw: "GET /.env 404"},
		{Time: now.Add(-6 * time.Minute), Source: logs.SourceNginx, Type: logs.TypeAccessSummary, Severity: logs.SevInfo, Fields: map[string]string{"requests": "120", "s4xx": "3", "s5xx": "1"}},
	}
	if err := s.Insert(ctx, srvA, "batch-0001", batch); err != nil {
		t.Fatal(err)
	}
	// reenvio do MESMO lote não duplica (deduplicação por token)
	if err := s.Insert(ctx, srvA, "batch-0001", batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, srvB, "batch-0002", batch[:1]); err != nil {
		t.Fatal(err)
	}

	f := Filter{ServerID: srvA, From: now.Add(-time.Hour), To: now.Add(time.Minute)}
	rows, total, err := s.List(ctx, f, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || len(rows) != 4 {
		t.Fatalf("total=%d rows=%d (deduplicação falhou? o resumo não entra na lista)", total, len(rows))
	}
	if !rows[0].Time.After(rows[1].Time) || rows[0].Type != logs.TypeAccess {
		t.Errorf("ordem decrescente esperada: %+v", rows[0])
	}
	fs := f
	fs.Type = logs.TypeAccessSummary
	if sum, n, _ := s.List(ctx, fs, 1, 10); n != 1 || len(sum) != 1 || sum[0].Fields["requests"] != "120" {
		t.Errorf("o resumo deve aparecer quando pedido por type: %d %+v", n, sum)
	}
	var ban Row
	for _, r := range rows {
		if r.Type == logs.TypeBan {
			ban = r
		}
	}
	if ban.IP != "203.0.113.9" || ban.Fields["jail"] != "sshd" || ban.ServerID != srvA || !ban.Time.Equal(now.Add(-10*time.Minute)) {
		t.Errorf("linha do ban: %+v", ban)
	}

	// filtros e paginação
	f2 := f
	f2.Source, f2.IP = logs.SourceFirewall, "203.0.113.9"
	if rows, total, _ = s.List(ctx, f2, 1, 10); total != 1 || len(rows) != 1 || rows[0].Port != 22 {
		t.Errorf("filtro source+ip: total=%d %+v", total, rows)
	}
	f3 := f
	f3.Q = "dpt=3306"
	if _, total, _ = s.List(ctx, f3, 1, 10); total != 1 {
		t.Errorf("busca q: total=%d", total)
	}
	if rows, total, _ = s.List(ctx, f, 2, 2); total != 4 || len(rows) != 2 {
		t.Errorf("paginação: total=%d len=%d", total, len(rows))
	}

	// injeção: o valor é parâmetro, não SQL
	f4 := f
	f4.Q = "'; DROP TABLE " + s.table() + "; --"
	f4.IP = "1.1.1.1' OR '1'='1"
	if _, total, err = s.List(ctx, f4, 1, 10); err != nil || total != 0 {
		t.Errorf("injeção: total=%d err=%v", total, err)
	}
	if _, total, _ = s.List(ctx, f, 1, 1); total != 4 {
		t.Error("a tabela foi afetada")
	}

	// isolamento por servidor
	if _, total, _ = s.List(ctx, Filter{ServerID: srvB, From: f.From, To: f.To}, 1, 10); total != 1 {
		t.Errorf("servidor B: %d", total)
	}

	st, err := s.Stats(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.TopIPs) == 0 || st.TopIPs[0].IP != "203.0.113.9" && st.TopIPs[0].IP != "198.51.100.7" {
		t.Errorf("top ips: %+v", st.TopIPs)
	}
	for _, ip := range st.TopIPs {
		if ip.IP == "203.0.113.9" && (ip.Bans != 1 || ip.Blocks != 1) {
			t.Errorf("ip agregado: %+v", ip)
		}
		if ip.IP == "198.51.100.7" && (ip.Blocks != 1 || ip.HTTPErrors != 1) {
			t.Errorf("ip agregado: %+v", ip)
		}
	}
	if len(st.TopPorts) != 2 || st.TopPorts[0].Blocks != 1 {
		t.Errorf("portas: %+v", st.TopPorts)
	}
	if len(st.Traffic) != 1 || st.Traffic[0].Requests != 120 || st.Traffic[0].Errors4 != 3 || st.Traffic[0].Errors5 != 1 {
		t.Errorf("tráfego: %+v", st.Traffic)
	}
	var total4 int64
	for _, p := range st.Timeline {
		total4 += p.Count
	}
	if total4 != 4 { // o resumo não entra na linha do tempo
		t.Errorf("timeline soma %d, esperado 4: %+v", total4, st.Timeline)
	}
	if st.BucketSecond != 60 {
		t.Errorf("bucket: %d", st.BucketSecond)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	for _, c := range []Config{{URL: ""}, {URL: "ftp://x"}, {URL: "http://x:8123", Database: "a; DROP"}} {
		if _, err := New(c); err == nil {
			t.Errorf("deveria rejeitar %+v", c)
		}
	}
}

func TestSystemMetricsInsertAndLatest(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.exec(ctx, "TRUNCATE TABLE "+s.systemTable(), nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	batch := []sysmetrics.Sample{
		{Time: now.Add(-3 * time.Minute), Metric: sysmetrics.OOMKills, Value: 1},
		{Time: now.Add(-2 * time.Minute), Metric: sysmetrics.OOMKills, Value: 2},
		{Time: now.Add(-2 * time.Minute), Metric: sysmetrics.InodeUsed, Subject: "/", Value: 50},
		{Time: now.Add(-time.Minute), Metric: sysmetrics.InodeUsed, Subject: "/", Value: 95},
		{Time: now.Add(-time.Minute), Metric: sysmetrics.InodeUsed, Subject: "/data", Value: 10},
	}
	if err := s.InsertSystem(ctx, srvA, "lote-0001", batch); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertSystem(ctx, srvA, "lote-0001", batch); err != nil { // reenvio não duplica
		t.Fatal(err)
	}
	old := []sysmetrics.Sample{{Time: now.Add(-time.Hour), Metric: sysmetrics.NTPUnsynced, Value: 1}}
	if err := s.InsertSystem(ctx, srvB, "lote-0002", old); err != nil {
		t.Fatal(err)
	}
	vals, err := s.LatestSystem(ctx, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]SystemValue{}
	for _, v := range vals {
		got[v.ServerID+"|"+v.Metric+"|"+v.Subject] = v
	}
	if len(got) != 3 {
		t.Fatalf("esperava 3 séries (dado fora da janela não conta): %+v", vals)
	}
	if o := got[srvA+"|oom_kills|"]; o.Sum != 3 || o.Latest != 2 {
		t.Errorf("oom: %+v", o)
	}
	if i := got[srvA+"|inode_used_percent|/"]; i.Latest != 95 {
		t.Errorf("inodes: %+v", i)
	}
}

func TestProcessHistory(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.exec(ctx, "TRUNCATE TABLE "+s.procTable(), nil); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * 30 * time.Second) }
	// 4 leituras; "node" aparece nas 4 (80% CPU), "backup" só em 1 (100% CPU) e "postgres" tem 2 workers em todas.
	for i := 0; i < 4; i++ {
		samples := []procs.TopSample{
			{At: at(i), PID: 10, Name: "node", User: "app", CPUPercent: 80, MemoryBytes: 100 << 20},
			{At: at(i), PID: 20, Name: "postgres", User: "pg", CPUPercent: 2, MemoryBytes: 500 << 20},
			{At: at(i), PID: 21, Name: "postgres", User: "pg", CPUPercent: 2, MemoryBytes: 300 << 20},
		}
		if i == 2 {
			samples = append(samples, procs.TopSample{At: at(i), PID: 30, Name: "backup", User: "root", CPUPercent: 100, MemoryBytes: 10 << 20})
		}
		if err := s.InsertProcTop(ctx, srvA, samples); err != nil {
			t.Fatal(err)
		}
		if i == 0 { // reenvio da mesma leitura não duplica
			if err := s.InsertProcTop(ctx, srvA, samples); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.InsertProcTop(ctx, srvB, []procs.TopSample{{At: at(0), PID: 99, Name: "outro", CPUPercent: 50}}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ProcTopRange(ctx, srvA, t0.Add(-time.Minute), t0.Add(time.Hour), 1000)
	if err != nil || len(rows) != 13 {
		t.Fatalf("faixa: %d linhas, %v", len(rows), err)
	}
	if !rows[0].At.Equal(at(0)) || rows[0].Name != "backup" && rows[0].Name != "node" || rows[0].CPUPercent != 80 {
		t.Errorf("ordem (instante, CPU desc): %+v", rows[0])
	}
	if sub, _ := s.ProcTopRange(ctx, srvA, at(1).Add(-time.Second), at(1).Add(time.Second), 1000); len(sub) != 3 {
		t.Errorf("recorte de uma leitura: %d", len(sub))
	}

	cpu, n, err := s.ProcCulprits(ctx, srvA, t0.Add(-time.Minute), t0.Add(time.Hour), procs.KindCPU, 3)
	if err != nil || n != 4 || len(cpu) != 3 {
		t.Fatalf("culpados cpu: n=%d %+v %v", n, cpu, err)
	}
	if cpu[0].Name != "node" || cpu[0].CPUPercent != 80 || cpu[0].CPUPeak != 80 {
		t.Errorf("node: %+v", cpu[0])
	}
	// backup: 100% em 1 de 4 leituras => média 25, pico 100; postgres: 2 workers somam 4% em todas
	if cpu[1].Name != "backup" || cpu[1].CPUPercent != 25 || cpu[1].CPUPeak != 100 || cpu[2].Name != "postgres" || cpu[2].CPUPercent != 4 {
		t.Errorf("demais: %+v", cpu[1:])
	}
	mem, _, err := s.ProcCulprits(ctx, srvA, t0.Add(-time.Minute), t0.Add(time.Hour), procs.KindMemory, 1)
	if err != nil || len(mem) != 1 || mem[0].Name != "postgres" || mem[0].MemoryBytes != 800<<20 {
		t.Errorf("memória (workers somados): %+v %v", mem, err)
	}
	if none, n, err := s.ProcCulprits(ctx, srvA, t0.Add(time.Hour), t0.Add(2*time.Hour), procs.KindCPU, 3); err != nil || n != 0 || len(none) != 0 {
		t.Errorf("janela vazia: %d %+v %v", n, none, err)
	}
}
