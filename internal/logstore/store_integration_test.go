//go:build integration

package logstore

import (
	"context"
	"os"
	"testing"
	"time"

	"sentinela/internal/logs"
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
	if total != 5 || len(rows) != 5 {
		t.Fatalf("total=%d rows=%d (deduplicação falhou?)", total, len(rows))
	}
	if !rows[0].Time.After(rows[1].Time) || rows[0].Type != logs.TypeAccessSummary {
		t.Errorf("ordem decrescente esperada: %+v", rows[0])
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
	if rows, total, _ = s.List(ctx, f, 2, 2); total != 5 || len(rows) != 2 {
		t.Errorf("paginação: total=%d len=%d", total, len(rows))
	}

	// injeção: o valor é parâmetro, não SQL
	f4 := f
	f4.Q = "'; DROP TABLE " + s.table() + "; --"
	f4.IP = "1.1.1.1' OR '1'='1"
	if _, total, err = s.List(ctx, f4, 1, 10); err != nil || total != 0 {
		t.Errorf("injeção: total=%d err=%v", total, err)
	}
	if _, total, _ = s.List(ctx, f, 1, 1); total != 5 {
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
