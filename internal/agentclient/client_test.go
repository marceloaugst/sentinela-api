package agentclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	base, max := time.Second, 30*time.Second
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i, w := range want {
		got := Backoff(i, base, max, 0.5) // jitter 0.5 => fator 1.0
		if got != w*time.Second {
			t.Errorf("tentativa %d: %v (esperado %v)", i, got, w*time.Second)
		}
	}
	lo, hi := Backoff(2, base, max, 0), Backoff(2, base, max, 0.999999)
	if lo >= 4*time.Second || hi <= 4*time.Second || lo < 3200*time.Millisecond || hi > 4800*time.Millisecond {
		t.Errorf("jitter fora de ±20%%: %v .. %v", lo, hi)
	}
}

func newTestClient(srvURL string) (*Client, *[]time.Duration) {
	var slept []time.Duration
	c := New(srvURL, "snt_tok", "test")
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	c.Jitter = func() float64 { return 0.5 }
	return c, &slept
}

func TestRetriesTransientThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer snt_tok" {
			t.Error("cabeçalho Authorization ausente")
		}
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"stored":true}}`))
	}))
	defer srv.Close()
	c, slept := newTestClient(srv.URL)
	var out struct{ Stored bool }
	if err := c.Do(context.Background(), "POST", "/x", map[string]int{"a": 1}, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Stored || calls.Load() != 3 {
		t.Errorf("out=%+v calls=%d", out, calls.Load())
	}
	if len(*slept) != 2 || (*slept)[0] != time.Second || (*slept)[1] != 2*time.Second {
		t.Errorf("backoff exponencial esperado 1s,2s: %v", *slept)
	}
}

func TestPermanentErrorsAreNotRetried(t *testing.T) {
	for _, status := range []int{401, 403, 422, 400} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"code":"X","message":"nao"}}`))
		}))
		c, _ := newTestClient(srv.URL)
		err := c.Do(context.Background(), "POST", "/x", nil, nil)
		var perm *PermanentError
		if !errors.As(err, &perm) || perm.Status != status || calls.Load() != 1 {
			t.Errorf("status %d: err=%v calls=%d", status, err, calls.Load())
		}
		if perm != nil && perm.IsAuth() != (status == 401 || status == 403) {
			t.Errorf("IsAuth incorreto para %d", status)
		}
		srv.Close()
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c, slept := newTestClient(srv.URL)
	if err := c.Do(context.Background(), "GET", "/x", nil, nil); err == nil {
		t.Fatal("esperava erro")
	}
	if calls.Load() != 4 || len(*slept) != 3 {
		t.Errorf("calls=%d sleeps=%d", calls.Load(), len(*slept))
	}
}

func TestHonorsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, slept := newTestClient(srv.URL)
	if err := c.Do(context.Background(), "POST", "/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(*slept) != 1 || (*slept)[0] != 7*time.Second {
		t.Errorf("deveria aguardar Retry-After (7s): %v", *slept)
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, _ := newTestClient(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	c.Sleep = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
	err := c.Do(ctx, "GET", "/x", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("esperava context.Canceled: %v", err)
	}
}

func TestNetworkErrorIsRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // porta fechada => erro de conexão
	c, slept := newTestClient(url)
	c.MaxAttempts = 3
	if err := c.Do(context.Background(), "GET", "/x", nil, nil); err == nil || len(*slept) != 2 {
		t.Errorf("err=%v sleeps=%d", err, len(*slept))
	}
}
