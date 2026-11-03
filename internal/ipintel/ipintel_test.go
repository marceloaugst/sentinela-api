package ipintel

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCache struct {
	rows  map[string]Info
	calls int
	limit int
}

func (f *fakeCache) Get(_ context.Context, ips []string) (map[string]Info, error) {
	out := map[string]Info{}
	for _, ip := range ips {
		if in, ok := f.rows[ip]; ok {
			out[ip] = in
		}
	}
	return out, nil
}

func (f *fakeCache) Put(_ context.Context, in Info) error { f.rows[in.IP] = in; return nil }

func (f *fakeCache) Reserve(_ context.Context, _ time.Time, limit int) (bool, error) {
	if f.calls >= limit {
		return false, nil
	}
	f.calls++
	return true, nil
}

func newTestService(t *testing.T, status int, hits *atomic.Int32) (*Service, *fakeCache) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Key") != "k" || r.URL.Path != "/api/v2/check" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"data":{"ipAddress":"`+r.URL.Query().Get("ipAddress")+`","countryCode":"CN","isp":"Example ISP",
			"usageType":"Data Center/Web Hosting/Transit","abuseConfidenceScore":87,"totalReports":42,"isTor":false,
			"lastReportedAt":"2026-10-28T10:00:00+00:00"}}`)
	}))
	t.Cleanup(srv.Close)
	fc := &fakeCache{rows: map[string]Info{}, limit: 1000}
	return &Service{
		Client: &Client{Key: "k", BaseURL: srv.URL, MaxAge: 90}, TTL: time.Hour, DailyLimit: 3,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), cache: fc,
	}, fc
}

func TestLookupCacheAndPrivate(t *testing.T) {
	var hits atomic.Int32
	s, _ := newTestService(t, 200, &hits)
	ctx := context.Background()

	got := s.Lookup(ctx, []string{"8.8.8.9", "10.0.0.1", "8.8.8.9", "127.0.0.1"})
	if in := got["8.8.8.9"]; in.CountryCode != "CN" || in.AbuseScore != 87 || in.TotalReports != 42 || in.LastReportedAt == nil {
		t.Fatalf("info inesperada: %+v", in)
	}
	if !got["10.0.0.1"].Private || !got["127.0.0.1"].Private {
		t.Fatalf("IP privado deveria ser marcado: %+v", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("esperava 1 consulta externa (duplicado e privados não consultam), houve %d", hits.Load())
	}
	s.Lookup(ctx, []string{"8.8.8.9"})
	if hits.Load() != 1 {
		t.Fatalf("segunda chamada deveria vir do cache, consultas = %d", hits.Load())
	}
}

func TestLookupDailyLimit(t *testing.T) {
	var hits atomic.Int32
	s, _ := newTestService(t, 200, &hits)
	s.HourlyLimit = 100 // aqui quem limita é a cota DIÁRIA (3), não o teto por hora
	got := s.Lookup(context.Background(), []string{"8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4", "8.8.8.5"})
	if len(got) != 3 || hits.Load() != 3 {
		t.Fatalf("a cota diária (3) deveria limitar as consultas: %d resultados, %d consultas", len(got), hits.Load())
	}
	// cota esgotada bloqueia novas consultas até o dia seguinte
	s.Lookup(context.Background(), []string{"8.8.8.6"})
	if hits.Load() != 3 {
		t.Fatalf("não deveria consultar com a cota esgotada")
	}
}

func TestLookupRateLimitedBlocksAndFailureBackoff(t *testing.T) {
	var hits atomic.Int32
	s, _ := newTestService(t, http.StatusTooManyRequests, &hits)
	s.DailyLimit = 100
	ctx := context.Background()
	if got := s.Lookup(ctx, []string{"8.8.8.1"}); len(got) != 0 {
		t.Fatalf("429 não deveria gerar resultado: %+v", got)
	}
	s.Lookup(ctx, []string{"8.8.8.2"})
	if hits.Load() != 1 {
		t.Fatalf("após 429 não deve haver novas consultas, houve %d", hits.Load())
	}

	var hits2 atomic.Int32
	s2, _ := newTestService(t, http.StatusInternalServerError, &hits2)
	s2.DailyLimit = 100
	s2.Lookup(ctx, []string{"8.8.8.1"})
	s2.Lookup(ctx, []string{"8.8.8.1"})
	if hits2.Load() != 1 {
		t.Fatalf("IP que falhou não deve ser repetido logo, consultas = %d", hits2.Load())
	}
}

func TestLookupWithoutKeyServesCacheOnly(t *testing.T) {
	var hits atomic.Int32
	s, fc := newTestService(t, 200, &hits)
	s.Client.Key = ""
	fc.rows["8.8.8.9"] = Info{IP: "8.8.8.9", CountryCode: "BR", FetchedAt: time.Now().Add(-48 * time.Hour)}
	got := s.Lookup(context.Background(), []string{"8.8.8.9", "8.8.8.10"})
	if got["8.8.8.9"].CountryCode != "BR" || len(got) != 1 || hits.Load() != 0 {
		t.Fatalf("sem chave deve servir só o cache (mesmo vencido): %+v, consultas %d", got, hits.Load())
	}
}

func TestIsPrivate(t *testing.T) {
	for ip, want := range map[string]bool{
		// privados, loopback, link-local
		"10.1.2.3": true, "192.168.0.1": true, "172.16.0.1": true, "::1": true, "127.0.0.1": true, "fe80::1": true, "169.254.1.1": true, "fd00::1": true,
		// faixas reservadas que não são de ninguém
		"100.64.0.1": true, "100.127.255.254": true, // CGNAT
		"198.18.0.1": true, "198.19.255.255": true, // testes de desempenho
		"192.0.2.1": true, "198.51.100.1": true, "203.0.113.1": true, // documentação
		"0.1.2.3": true, "240.0.0.1": true, "255.255.255.255": true, "192.0.0.8": true, "192.88.99.1": true,
		"2001:db8::1": true, "3fff::1": true, "64:ff9b::808:808": true, "100::1": true, "2001:1::1": true,
		// IPv4 mapeado em IPv6 vale como o IPv4
		"::ffff:10.0.0.1": true, "::ffff:100.64.0.1": true, "::ffff:8.8.8.8": false,
		// públicos (vizinhos das faixas acima não podem ser pegos por engano)
		"8.8.8.8": false, "1.1.1.1": false, "100.63.255.255": false, "100.128.0.1": false, "198.17.255.255": false,
		"198.20.0.1": false, "203.0.114.1": false, "239.0.0.1": true, "2001:4860:4860::8888": false, "2606:4700::1111": false,
		"lixo": false,
	} {
		if IsPrivate(ip) != want {
			t.Errorf("IsPrivate(%q) = %v; esperado %v", ip, !want, want)
		}
	}
}

// Faixas não públicas e texto que não é IP nunca chegam à rede nem à cota.
func TestLookupNeverQueriesNonPublic(t *testing.T) {
	var hits atomic.Int32
	s, fc := newTestService(t, 200, &hits)
	nonPublic := []string{"100.64.1.2", "198.18.0.9", "192.0.2.5", "198.51.100.5", "203.0.113.5", "240.0.0.1", "2001:db8::1", "::ffff:100.64.0.1"}
	got := s.Lookup(context.Background(), append([]string{"lixo", "999.1.1.1", ""}, nonPublic...))
	if hits.Load() != 0 || fc.calls != 0 {
		t.Fatalf("não deveria consultar nada: %d consultas, %d reservas de cota", hits.Load(), fc.calls)
	}
	for _, ip := range nonPublic {
		if !got[ip].Private {
			t.Errorf("%s deveria vir como private: %+v", ip, got[ip])
		}
	}
	for _, bad := range []string{"lixo", "999.1.1.1", ""} {
		if _, ok := got[bad]; ok {
			t.Errorf("texto que não é IP não deveria ter entrada: %q", bad)
		}
	}
}

// O teto por hora segura a consulta externa e NÃO gasta a cota diária das consultas que nega.
func TestLookupHourlyLimit(t *testing.T) {
	var hits atomic.Int32
	s, fc := newTestService(t, 200, &hits)
	s.DailyLimit, s.HourlyLimit = 100, 2
	ctx := context.Background()
	got := s.Lookup(ctx, []string{"8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4", "8.8.8.5"})
	if len(got) != 2 || hits.Load() != 2 {
		t.Fatalf("o teto por hora (2) deveria limitar: %d resultados, %d consultas", len(got), hits.Load())
	}
	if fc.calls != 2 {
		t.Errorf("consultas negadas pelo teto não podem gastar a cota diária: %d reservas", fc.calls)
	}
	s.Lookup(ctx, []string{"8.8.8.6", "8.8.8.7"})
	if hits.Load() != 2 {
		t.Errorf("com o teto esgotado não deveria consultar: %d consultas", hits.Load())
	}
	// o que já está em cache continua sendo servido sem gastar o teto
	if g := s.Lookup(ctx, []string{"8.8.8.1"}); g["8.8.8.1"].CountryCode != "CN" || hits.Load() != 2 {
		t.Errorf("cache deveria servir: %+v, consultas %d", g, hits.Load())
	}
}

func TestDefaultHourlyLimit(t *testing.T) {
	for daily, want := range map[int]int{1000: 83, 120: 10, 100: 10, 24: 10, 3: 3, 1: 1, 0: 1} {
		if got := DefaultHourlyLimit(daily); got != want {
			t.Errorf("DefaultHourlyLimit(%d) = %d; esperado %d", daily, got, want)
		}
	}
}
