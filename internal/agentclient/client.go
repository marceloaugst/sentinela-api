// Package agentclient envia dados do agente para a API central com retentativas
// e backoff exponencial.
package agentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// PermanentError indica rejeição que não deve ser retentada (ex.: 401, 403, 422).
type PermanentError struct {
	Status  int
	Code    string
	Message string
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("API rejeitou a requisição (HTTP %d %s): %s", e.Status, e.Code, e.Message)
}

// IsAuth informa se a rejeição é de credencial (token inválido/revogado/servidor desativado).
func (e *PermanentError) IsAuth() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client

	MaxAttempts int           // tentativas por envio
	BaseDelay   time.Duration // backoff inicial
	MaxDelay    time.Duration // teto do backoff
	UserAgent   string

	// injetáveis em testes
	Sleep  func(ctx context.Context, d time.Duration) error
	Jitter func() float64 // [0,1)
}

func New(baseURL, token, userAgent string) *Client {
	return &Client{
		BaseURL: baseURL, Token: token, UserAgent: userAgent,
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		MaxAttempts: 4, BaseDelay: time.Second, MaxDelay: 30 * time.Second,
		Sleep:  sleep,
		Jitter: rand.Float64,
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Backoff: base * 2^attempt (attempt começa em 0), limitado por max, com jitter de ±20%.
func Backoff(attempt int, base, max time.Duration, jitter float64) time.Duration {
	d := base
	for i := 0; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	factor := 0.8 + 0.4*jitter
	return time.Duration(float64(d) * factor)
}

type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Do envia a requisição, retentando falhas transitórias (rede, 408, 429, 5xx).
// Se out != nil, decodifica o campo "data" da resposta.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	var lastErr error
	for attempt := 0; attempt < c.MaxAttempts; attempt++ {
		retryAfter, err := c.once(ctx, method, path, payload, out)
		if err == nil {
			return nil
		}
		var perm *PermanentError
		if errors.As(err, &perm) || ctx.Err() != nil {
			return err
		}
		lastErr = err
		if attempt == c.MaxAttempts-1 {
			break
		}
		delay := Backoff(attempt, c.BaseDelay, c.MaxDelay, c.Jitter())
		if retryAfter > delay {
			delay = min(retryAfter, c.MaxDelay)
		}
		if err := c.Sleep(ctx, delay); err != nil {
			return err
		}
	}
	return fmt.Errorf("falha após %d tentativas: %w", c.MaxAttempts, lastErr)
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, out any) (time.Duration, error) {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, &PermanentError{Message: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err // erro de rede: transitório
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return 0, nil
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return 0, fmt.Errorf("resposta inválida: %w", err)
		}
		return 0, json.Unmarshal(env.Data, out)
	}

	var env envelope
	_ = json.Unmarshal(raw, &env)
	perm := &PermanentError{Status: resp.StatusCode}
	if env.Error != nil {
		perm.Code, perm.Message = env.Error.Code, env.Error.Message
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		secs, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return time.Duration(secs) * time.Second, fmt.Errorf("limitado pela API (429)")
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500:
		return 0, fmt.Errorf("erro transitório da API (HTTP %d)", resp.StatusCode)
	default:
		return 0, perm
	}
}
