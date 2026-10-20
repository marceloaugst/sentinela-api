package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinela/internal/config"
	"sentinela/internal/telemetry"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestRouter(db fakeDB) nethttp.Handler {
	return NewRouter(Deps{
		Config:  config.Config{MaxBodyBytes: 1 << 10, RequestTimeout: 5e9},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: telemetry.NewMetrics(),
		DB:      db,
		Version: "test",
	})
}

func do(h nethttp.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHealthz(t *testing.T) {
	rec := do(newTestRouter(fakeDB{}), "GET", "/healthz")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestReadyz(t *testing.T) {
	if rec := do(newTestRouter(fakeDB{}), "GET", "/readyz"); rec.Code != 200 {
		t.Errorf("com banco: %d", rec.Code)
	}
	rec := do(newTestRouter(fakeDB{err: errors.New("conexão recusada em 10.0.0.5:5432")}), "GET", "/readyz")
	if rec.Code != 503 {
		t.Fatalf("sem banco: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("vazou detalhe interno: %s", rec.Body)
	}
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error.Code != "NOT_READY" {
		t.Errorf("código: %s", rec.Body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	h := newTestRouter(fakeDB{})
	do(h, "GET", "/healthz")
	rec := do(h, "GET", "/metrics")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "sentinela_http_requests_total") {
		t.Errorf("%d %.200s", rec.Code, rec.Body)
	}
}

func TestNotFoundAndMethodNotAllowedUseEnvelope(t *testing.T) {
	h := newTestRouter(fakeDB{})
	rec := do(h, "GET", "/nada")
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"code":"NOT_FOUND"`) {
		t.Errorf("404: %d %s", rec.Code, rec.Body)
	}
	rec = do(h, "POST", "/healthz")
	if rec.Code != 405 || !strings.Contains(rec.Body.String(), "METHOD_NOT_ALLOWED") {
		t.Errorf("405: %d %s", rec.Code, rec.Body)
	}
}
