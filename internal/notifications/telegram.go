package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const DefaultTelegramBase = "https://api.telegram.org"

// SendError classifica a falha para decidir entre retentar e desistir.
type SendError struct {
	Permanent  bool          // 400/401/403/404: não adianta retentar
	RetryAfter time.Duration // pedido do servidor (429)
	Reason     string        // sem token nem URL
}

func (e *SendError) Error() string { return e.Reason }

type Sender interface {
	Send(ctx context.Context, token, chatID, text string) error
}

type Telegram struct {
	BaseURL string
	HTTP    *http.Client
}

func NewTelegram(baseURL string) *Telegram {
	if baseURL == "" {
		baseURL = DefaultTelegramBase
	}
	return &Telegram{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type tgResponse struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Send envia texto puro (sem parse_mode, logo sem risco de injeção de formatação).
// Nenhum erro devolvido contém o token: ele faz parte da URL e o http.Client o incluiria.
func (t *Telegram) Send(ctx context.Context, token, chatID, text string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": chatID, "text": truncate(text, 4000), "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.BaseURL+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return &SendError{Permanent: true, Reason: "requisição inválida"}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		reason := "falha de rede ao contatar o Telegram"
		if errors.Is(err, context.DeadlineExceeded) {
			reason = "tempo limite ao contatar o Telegram"
		}
		return &SendError{Reason: reason}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out tgResponse
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode == http.StatusOK && out.OK {
		return nil
	}
	desc := out.Description
	if desc == "" {
		desc = http.StatusText(resp.StatusCode)
	}
	desc = strings.ReplaceAll(desc, token, "***")
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return &SendError{RetryAfter: time.Duration(out.Parameters.RetryAfter) * time.Second, Reason: "limite do Telegram (429): " + desc}
	case resp.StatusCode >= 500:
		return &SendError{Reason: fmt.Sprintf("erro do Telegram (HTTP %d)", resp.StatusCode)}
	default: // 400 (chat não encontrado...), 401 (token inválido), 403 (bot bloqueado), 404
		return &SendError{Permanent: true, Reason: fmt.Sprintf("Telegram recusou (HTTP %d): %s", resp.StatusCode, desc)}
	}
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}

// FormatText monta a mensagem: servidor, tipo do problema, horário e severidade.
func FormatText(p Payload) string {
	if p.Kind == KindTest {
		return "🔔 Teste do Sentinela: o canal de notificações está funcionando."
	}
	if p.Kind == KindIPBanned {
		return fmt.Sprintf("🚫 [P3 · aviso] %s\nIP banido pelo fail2ban: %s\n%s\nHorário: %s", p.ServerName, p.RuleName, p.Message,
			p.At.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	icon, label := map[string]string{"critical": "🔴", "warning": "🟠", "info": "🔵"}[p.Severity], strings.ToUpper(sevPT(p.Severity))
	if p.Priority > 0 {
		label = fmt.Sprintf("P%d · %s", p.Priority, label)
	}
	head := fmt.Sprintf("%s [%s] %s", icon, label, p.ServerName)
	if p.Recurrence > 0 && p.Kind != KindResolved {
		head += fmt.Sprintf(" (reincidente: %d× em 24 h)", p.Recurrence)
	}
	when := "Início"
	if p.Kind == KindResolved {
		head = fmt.Sprintf("✅ [RECUPERADO] %s", p.ServerName)
		when = "Recuperado em"
	}
	subject := p.RuleName
	if p.ServiceName != "" {
		subject += " — " + p.ServiceName
	}
	return fmt.Sprintf("%s\n%s\n%s\n%s: %s", head, subject, p.Message, when, p.At.UTC().Format("2006-01-02 15:04:05 UTC"))
}

func sevPT(s string) string {
	switch s {
	case "critical":
		return "crítico"
	case "warning":
		return "aviso"
	case "info":
		return "info"
	}
	return s
}
