package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sentinela/internal/ipintel"
	"sentinela/internal/logstore"
)

type fakeCountryStore struct{ LogStore }

func (fakeCountryStore) Ready() bool { return true }
func (fakeCountryStore) IPTotals(context.Context, logstore.Filter, string, int) ([]logstore.IPTotal, int64, error) {
	return []logstore.IPTotal{{IP: "1.1.1.1", Count: 10}, {IP: "1.1.1.2", Count: 6}, {IP: "2.2.2.2", Count: 5},
		{IP: "10.0.0.1", Count: 3}, {IP: "3.3.3.3", Count: 2}}, 30, nil // 4 de 30 ficam fora do limite
}

type fakeIntel map[string]ipintel.Info

func (f fakeIntel) Lookup(_ context.Context, ips []string) map[string]ipintel.Info {
	out := map[string]ipintel.Info{}
	for _, ip := range ips {
		if in, ok := f[ip]; ok {
			out[ip] = in
		}
	}
	return out
}

func TestCountries(t *testing.T) {
	h := &Logs{Store: fakeCountryStore{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return time.Date(2026, 10, 29, 14, 20, 0, 0, time.UTC) },
		Intel: fakeIntel{
			"1.1.1.1":  {CountryCode: "BR", AbuseScore: 30},
			"1.1.1.2":  {CountryCode: "BR", AbuseScore: 39},
			"2.2.2.2":  {CountryCode: "US", AbuseScore: 71},
			"10.0.0.1": {Private: true},
		}}
	rec := httptest.NewRecorder()
	h.Countries(rec, httptest.NewRequest("GET", "/logs/countries?days=7", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var resp struct{ Data countriesOut }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	d := resp.Data
	if d.GeneratedAt != "2026-10-29T14:20:00Z" || d.PeriodDays != 7 || d.Metric != "events" || d.Total != 30 || len(d.Countries) != 2 {
		t.Fatalf("resposta: %+v", d)
	}
	if c := d.Countries[0]; c.Code != "BR" || c.Name != "Brazil" || c.Events != 16 || c.IPs != 2 || c.AvgScore != 35 {
		t.Fatalf("BR: %+v", c)
	}
	// 3.3.3.3 (não consultado) + 10.0.0.1 (privado) + 4 fora do limite... = 2+3 + (30-26)
	if d.Unknown.Events != 9 || d.Unknown.IPs != 2 {
		t.Fatalf("unknown: %+v", d.Unknown)
	}

	rec = httptest.NewRecorder()
	h.Countries(rec, httptest.NewRequest("GET", "/logs/countries?days=99&metric=x", nil))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("esperava 422, veio %d", rec.Code)
	}
}
