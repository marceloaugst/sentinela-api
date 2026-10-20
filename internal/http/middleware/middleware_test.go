package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinela/internal/telemetry"
)

func ok() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRequestIDGeneratedAndReused(t *testing.T) {
	h := RequestID(ok())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if len(rec.Header().Get(RequestIDHeader)) != 16 {
		t.Errorf("id gerado: %q", rec.Header().Get(RequestIDHeader))
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(RequestIDHeader, "abc-123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get(RequestIDHeader) != "abc-123" {
		t.Error("deveria reaproveitar ID válido")
	}

	req.Header.Set(RequestIDHeader, "bad id\r\nX: y")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get(RequestIDHeader) == "bad id\r\nX: y" {
		t.Error("não deveria reaproveitar ID inválido")
	}
}

func TestRecoverHidesInternals(t *testing.T) {
	m := telemetry.NewMetrics()
	h := Recover(quiet(), m)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("segredo-interno") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "segredo-interno") || strings.Contains(rec.Body.String(), "goroutine") {
		t.Errorf("vazou detalhe interno: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "INTERNAL_ERROR") {
		t.Errorf("corpo: %s", rec.Body)
	}
}

func TestBodyLimit(t *testing.T) {
	read := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(200)
	})
	h := BodyLimit(10)(read)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("0123456789ABC")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("com Content-Length: %d", rec.Code)
	}

	req := httptest.NewRequest("POST", "/", strings.NewReader("0123456789ABC"))
	req.ContentLength = -1 // chunked
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("sem Content-Length: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("ok")))
	if rec.Code != 200 {
		t.Errorf("corpo pequeno: %d", rec.Code)
	}
}

func TestCORS(t *testing.T) {
	h := CORS([]string{"https://app.example.com"})(ok())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
		rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("origem permitida: %v", rec.Header())
	}

	req.Header.Set("Origin", "https://evil.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("origem não permitida recebeu cabeçalho CORS")
	}

	pre := httptest.NewRequest("OPTIONS", "/", nil)
	pre.Header.Set("Origin", "https://app.example.com")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, pre)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("preflight: %d %v", rec.Code, rec.Header())
	}

	pre.Header.Set("Origin", "https://evil.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, pre)
	if rec.Code != http.StatusForbidden {
		t.Errorf("preflight negado: %d", rec.Code)
	}
}

func TestCORSEmptyAllowListNeverAllows(t *testing.T) {
	h := CORS(nil)(ok())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://x.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("lista vazia não deve permitir origens")
	}
}

func TestTimeoutSetsDeadline(t *testing.T) {
	h := Timeout(time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, has := r.Context().Deadline(); !has {
			t.Error("sem deadline")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestObserveCountsStatusAndErrors(t *testing.T) {
	m := telemetry.NewMetrics()
	h := Observe(quiet(), m)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "sentinela_http_requests_total" {
			found = true
			lbl := mf.GetMetric()[0].GetLabel()
			var status string
			for _, l := range lbl {
				if l.GetName() == "status" {
					status = l.GetValue()
				}
			}
			if status != "502" {
				t.Errorf("status label %q", status)
			}
		}
	}
	if !found {
		t.Error("métrica de requisições não registrada")
	}
}
