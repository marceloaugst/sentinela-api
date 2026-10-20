package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const tok = "123456789:AAH-testtoken_abcdefghijklmnopqrstuvwxyz1234"

func TestSendSuccessAndRequestShape(t *testing.T) {
	var gotPath, gotCT string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotCT = r.URL.Path, r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()
	if err := NewTelegram(srv.URL).Send(context.Background(), tok, "-1001", "olá"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+tok+"/sendMessage" || gotCT != "application/json" {
		t.Errorf("%s %s", gotPath, gotCT)
	}
	if body["chat_id"] != "-1001" || body["text"] != "olá" || body["parse_mode"] != nil {
		t.Errorf("corpo: %v (sem parse_mode: texto puro)", body)
	}
}

func TestSendErrorClassification(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		permanent bool
		retry     time.Duration
	}{
		{"429 com retry_after", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`, false, 7 * time.Second},
		{"500", 500, `{}`, false, 0},
		{"502", 502, ``, false, 0},
		{"400 chat não encontrado", 400, `{"ok":false,"description":"Bad Request: chat not found"}`, true, 0},
		{"401 token inválido", 401, `{"ok":false,"description":"Unauthorized"}`, true, 0},
		{"403 bot bloqueado", 403, `{"ok":false,"description":"Forbidden: bot was blocked by the user"}`, true, 0},
		{"200 mas ok=false", 200, `{"ok":false}`, true, 0},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		err := NewTelegram(srv.URL).Send(context.Background(), tok, "1", "x")
		srv.Close()
		var se *SendError
		if !errors.As(err, &se) {
			t.Errorf("%s: esperava SendError, obteve %v", c.name, err)
			continue
		}
		if se.Permanent != c.permanent || se.RetryAfter != c.retry {
			t.Errorf("%s: permanent=%v retry=%v", c.name, se.Permanent, se.RetryAfter)
		}
	}
}

func TestTokenNeverLeaksInErrors(t *testing.T) {
	// descrição do servidor ecoando o token
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"ok":false,"description":"bad token ` + tok + `"}`))
	}))
	err := NewTelegram(srv.URL).Send(context.Background(), tok, "1", "x")
	srv.Close()
	if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "AAH-test") {
		t.Errorf("token vazou: %v", err)
	}
	// erro de rede: http.Client incluiria a URL (com o token) no erro
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv2.URL
	srv2.Close()
	err = NewTelegram(url).Send(context.Background(), tok, "1", "x")
	var se *SendError
	if !errors.As(err, &se) || se.Permanent || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "bot") {
		t.Errorf("erro de rede deveria ser transitório e sem URL/token: %v", err)
	}
}

func TestFormatText(t *testing.T) {
	at := time.Date(2026, 3, 1, 14, 3, 5, 0, time.UTC)
	trig := FormatText(Payload{Kind: KindTriggered, ServerName: "web-1", RuleName: "CPU alta", Severity: "critical", Message: "Uso de CPU em 95.0% (limite: > 90%)", At: at})
	for _, want := range []string{"🔴", "CRÍTICO", "web-1", "CPU alta", "95.0%", "2026-03-01 14:03:05 UTC"} {
		if !strings.Contains(trig, want) {
			t.Errorf("faltou %q em:\n%s", want, trig)
		}
	}
	rec := FormatText(Payload{Kind: KindResolved, ServerName: "web-1", ServiceName: "api", RuleName: "Serviço fora", Severity: "critical", Message: "Recuperado: x", At: at})
	if !strings.Contains(rec, "✅") || !strings.Contains(rec, "RECUPERADO") || !strings.Contains(rec, "Serviço fora — api") {
		t.Errorf("recuperação:\n%s", rec)
	}
	if !strings.Contains(FormatText(Payload{Kind: KindTest}), "Teste") {
		t.Error("teste")
	}
	long := FormatText(Payload{Kind: KindTriggered, ServerName: "s", Severity: "info", Message: strings.Repeat("x", 9000), At: at})
	_ = long
	if got := truncate(strings.Repeat("é", 5000), 4000); len([]rune(got)) != 4000 {
		t.Errorf("truncate: %d", len([]rune(got)))
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	prev := time.Duration(0)
	for a := 1; a <= 4; a++ {
		d := DefaultBackoff(a)
		lo := time.Duration(float64(30*time.Second<<(a-1)) * 0.79)
		hi := time.Duration(float64(30*time.Second<<(a-1)) * 1.21)
		if d < lo || d > hi {
			t.Errorf("tentativa %d: %v fora de [%v, %v]", a, d, lo, hi)
		}
		if a > 1 && d < prev/2 {
			t.Errorf("backoff não cresce: %v -> %v", prev, d)
		}
		prev = d
	}
	if d := DefaultBackoff(30); d > 37*time.Minute {
		t.Errorf("teto de 30 min (+20%%) excedido: %v", d)
	}
}

func TestRank(t *testing.T) {
	if !(Rank("info") < Rank("warning") && Rank("warning") < Rank("critical") && Rank("x") == 0) {
		t.Error("ordem de gravidade")
	}
}

func TestChannelValidation(t *testing.T) {
	ok := CreateInput{Name: "ops", BotToken: tok, ChatID: "-1001234567890"}
	if p := ok.Validate(); len(p) != 0 || ok.MinSeverity != "critical" || ok.Type != "telegram" {
		t.Errorf("%v %+v", p, ok)
	}
	for name, in := range map[string]CreateInput{
		"token inválido":     {Name: "a", BotToken: "abc", ChatID: "1"},
		"chat inválido":      {Name: "a", BotToken: tok, ChatID: "abc def"},
		"sem nome":           {Name: "", BotToken: tok, ChatID: "1"},
		"severidade":         {Name: "a", BotToken: tok, ChatID: "1", MinSeverity: "fatal"},
		"tipo não suportado": {Name: "a", Type: "slack", BotToken: tok, ChatID: "1"},
	} {
		in := in
		if p := in.Validate(); len(p) == 0 {
			t.Errorf("%s deveria falhar", name)
		}
	}
	ch := CreateInput{Name: "a", BotToken: tok, ChatID: "@meu_canal"}
	if p := ch.Validate(); len(p) != 0 {
		t.Errorf("@canal: %v", p)
	}
	if p := (&UpdateInput{}).Validate(); len(p) != 1 {
		t.Errorf("patch vazio: %v", p)
	}
	bad := "x"
	if p := (&UpdateInput{BotToken: &bad}).Validate(); len(p) != 1 {
		t.Errorf("token inválido no patch: %v", p)
	}
}

func TestChatAllowedIsSecureByDefault(t *testing.T) {
	r := NewChannelRepository(nil, nil, nil)
	if r.ChatAllowed("123") || r.ChatAllowed("") {
		t.Error("sem lista configurada nada deve ser autorizado")
	}
	r = NewChannelRepository(nil, nil, []string{" -100 ", "42", ""})
	if !r.ChatAllowed("-100") || !r.ChatAllowed("42") || r.ChatAllowed("43") {
		t.Error("lista de autorizados")
	}
}
