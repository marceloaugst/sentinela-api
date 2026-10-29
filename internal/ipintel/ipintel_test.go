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

	got := s.Lookup(ctx, []string{"203.0.113.9", "10.0.0.1", "203.0.113.9", "127.0.0.1"})
	if in := got["203.0.113.9"]; in.CountryCode != "CN" || in.AbuseScore != 87 || in.TotalReports != 42 || in.LastReportedAt == nil {
		t.Fatalf("info inesperada: %+v", in)
	}
	if !got["10.0.0.1"].Private || !got["127.0.0.1"].Private {
		t.Fatalf("IP privado deveria ser marcado: %+v", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("esperava 1 consulta externa (duplicado e privados não consultam), houve %d", hits.Load())
	}
	s.Lookup(ctx, []string{"203.0.113.9"})
	if hits.Load() != 1 {
		t.Fatalf("segunda chamada deveria vir do cache, consultas = %d", hits.Load())
	}
}

func TestLookupDailyLimit(t *testing.T) {
	var hits atomic.Int32
	s, _ := newTestService(t, 200, &hits)
	got := s.Lookup(context.Background(), []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"})
	if len(got) != 3 || hits.Load() != 3 {
		t.Fatalf("a cota diária (3) deveria limitar as consultas: %d resultados, %d consultas", len(got), hits.Load())
	}
	// cota esgotada bloqueia novas consultas até o dia seguinte
	s.Lookup(context.Background(), []string{"203.0.113.6"})
	if hits.Load() != 3 {
		t.Fatalf("não deveria consultar com a cota esgotada")
	}
}

func TestLookupRateLimitedBlocksAndFailureBackoff(t *testing.T) {
	var hits atomic.Int32
	s, _ := newTestService(t, http.StatusTooManyRequests, &hits)
	s.DailyLimit = 100
	ctx := context.Background()
	if got := s.Lookup(ctx, []string{"203.0.113.1"}); len(got) != 0 {
		t.Fatalf("429 não deveria gerar resultado: %+v", got)
	}
	s.Lookup(ctx, []string{"203.0.113.2"})
	if hits.Load() != 1 {
		t.Fatalf("após 429 não deve haver novas consultas, houve %d", hits.Load())
	}

	var hits2 atomic.Int32
	s2, _ := newTestService(t, http.StatusInternalServerError, &hits2)
	s2.DailyLimit = 100
	s2.Lookup(ctx, []string{"203.0.113.1"})
	s2.Lookup(ctx, []string{"203.0.113.1"})
	if hits2.Load() != 1 {
		t.Fatalf("IP que falhou não deve ser repetido logo, consultas = %d", hits2.Load())
	}
}

func TestLookupWithoutKeyServesCacheOnly(t *testing.T) {
	var hits atomic.Int32
	s, fc := newTestService(t, 200, &hits)
	s.Client.Key = ""
	fc.rows["203.0.113.9"] = Info{IP: "203.0.113.9", CountryCode: "BR", FetchedAt: time.Now().Add(-48 * time.Hour)}
	got := s.Lookup(context.Background(), []string{"203.0.113.9", "203.0.113.10"})
	if got["203.0.113.9"].CountryCode != "BR" || len(got) != 1 || hits.Load() != 0 {
		t.Fatalf("sem chave deve servir só o cache (mesmo vencido): %+v, consultas %d", got, hits.Load())
	}
}

func TestIsPrivate(t *testing.T) {
	for ip, want := range map[string]bool{"10.1.2.3": true, "192.168.0.1": true, "::1": true, "fe80::1": true, "169.254.1.1": true,
		"8.8.8.8": false, "2001:4860:4860::8888": false, "lixo": false} {
		if IsPrivate(ip) != want {
			t.Errorf("IsPrivate(%q) = %v", ip, !want)
		}
	}
}
