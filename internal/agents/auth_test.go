package agents

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinela/internal/ratelimit"
)

type fakeStore struct {
	known map[string]Identity
	err   error
	calls int
}

func (f *fakeStore) Authenticate(_ context.Context, hash []byte) (Identity, error) {
	f.calls++
	if f.err != nil {
		return Identity{}, f.err
	}
	for tok, id := range f.known {
		if string(HashToken(tok)) == string(hash) {
			return id, nil
		}
	}
	return Identity{}, ErrInvalidCredential
}

func setup(t *testing.T, status string) (*Auth, *fakeStore, string, http.Handler) {
	t.Helper()
	tok, _, _ := GenerateToken()
	st := &fakeStore{known: map[string]Identity{tok: {CredentialID: "c1", ServerID: "s1", ServerStatus: status}}}
	a := NewAuth(st, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	var got Identity
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = IdentityFrom(r.Context())
		if got.ServerID != "s1" {
			t.Errorf("identidade no contexto: %+v", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return a, st, tok, h
}

func call(h http.Handler, authz string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthMissingOrMalformedTokenSkipsDatabase(t *testing.T) {
	_, st, _, h := setup(t, "active")
	for _, authz := range []string{"", "Bearer abc", "Basic xyz"} {
		if rec := call(h, authz); rec.Code != 401 {
			t.Errorf("%q: %d", authz, rec.Code)
		}
	}
	if st.calls != 0 {
		t.Errorf("formato inválido não deveria consultar o banco (%d consultas)", st.calls)
	}
}

func TestAuthValidUnknownAndDisabled(t *testing.T) {
	_, _, tok, h := setup(t, "active")
	if rec := call(h, "Bearer "+tok); rec.Code != 204 {
		t.Errorf("válido: %d", rec.Code)
	}
	other, _, _ := GenerateToken()
	if rec := call(h, "Bearer "+other); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("desconhecido: %d", rec.Code)
	}
	_, _, tok2, h2 := setup(t, "disabled")
	if rec := call(h2, "Bearer "+tok2); rec.Code != 403 || !strings.Contains(rec.Body.String(), "SERVER_DISABLED") {
		t.Errorf("desativado: %d %s", rec.Code, rec.Body)
	}
	// manutenção continua aceitando dados
	_, _, tok3, h3 := setup(t, "maintenance")
	if rec := call(h3, "Bearer "+tok3); rec.Code != 204 {
		t.Errorf("manutenção: %d", rec.Code)
	}
}

func TestAuthStoreErrorIs500WithoutDetails(t *testing.T) {
	_, st, tok, h := setup(t, "active")
	st.err = errors.New("pq: connection to 10.1.1.1 refused")
	rec := call(h, "Bearer "+tok)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "10.1.1.1") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestAuthRateLimitPerCredential(t *testing.T) {
	a, _, tok, h := setup(t, "active")
	a.ByCred = ratelimit.New(0.001, 3)
	for i := 0; i < 3; i++ {
		if rec := call(h, "Bearer "+tok); rec.Code != 204 {
			t.Fatalf("req %d: %d", i, rec.Code)
		}
	}
	rec := call(h, "Bearer "+tok)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("esperava 429 com Retry-After: %d %v", rec.Code, rec.Header())
	}
}

func TestAuthRateLimitPerIPBlocksBeforeLookup(t *testing.T) {
	a, st, _, h := setup(t, "active")
	a.ByIP = ratelimit.New(0.001, 2)
	other, _, _ := GenerateToken()
	call(h, "Bearer "+other)
	call(h, "Bearer "+other)
	before := st.calls
	if rec := call(h, "Bearer "+other); rec.Code != 429 {
		t.Errorf("esperava 429: %d", rec.Code)
	}
	if st.calls != before {
		t.Error("IP limitado não deveria consultar o banco")
	}
}
