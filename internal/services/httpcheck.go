package services

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"sentinela/internal/ssrf"
)

const maxBodyRead = 64 << 10

// Checker executa verificações HTTP aplicando a política anti-SSRF na conexão.
type Checker struct {
	Policy ssrf.Policy
	client *http.Client
}

func NewChecker(policy ssrf.Policy) *Checker {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: policy.Control}
	tr := &http.Transport{
		DialContext:            d.DialContext,
		Proxy:                  nil, // proxies do ambiente poderiam contornar a política
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &Checker{Policy: policy, client: &http.Client{
		Transport: tr,
		// Redirecionamentos NÃO são seguidos: um 3xx é avaliado pelo expected_status. Isso evita
		// que um alvo externo redirecione a verificação para um destino interno.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func intp(v int) *int { return &v }

// Check devolve sempre um Result; mensagens de erro são genéricas (sem detalhes internos).
func (c *Checker) Check(ctx context.Context, target string, cfg Config) Result {
	if _, err := c.Policy.ValidateURL(target); err != nil {
		return Result{Status: StatusDown, Error: "destino não permitido pela política de segurança"}
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := cfg.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return Result{Status: StatusDown, Error: "URL inválida"}
	}
	req.Header.Set("User-Agent", "Sentinela-Check/1.0")

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return Result{Status: StatusDown, Error: classify(err)}
	}
	defer resp.Body.Close()

	var body []byte
	if cfg.BodyContains != "" {
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
		if err != nil {
			return Result{Status: StatusDown, StatusCode: intp(resp.StatusCode), Error: classify(err)}
		}
	}
	latency := int(time.Since(start).Milliseconds())
	res := Result{LatencyMS: intp(latency), StatusCode: intp(resp.StatusCode)}

	expected := cfg.ExpectedStatus
	if len(expected) == 0 {
		expected = []int{200}
	}
	statusOK := false
	for _, s := range expected {
		if s == resp.StatusCode {
			statusOK = true
		}
	}
	switch {
	case !statusOK:
		res.Status, res.Error = StatusDown, "código HTTP inesperado: "+itoa(resp.StatusCode)
	case cfg.BodyContains != "" && !strings.Contains(string(body), cfg.BodyContains):
		res.Status, res.Error = StatusDown, "o corpo da resposta não contém o texto esperado"
	case cfg.MaxLatencyMS > 0 && latency > cfg.MaxLatencyMS:
		res.Status, res.Error = StatusDegraded, "latência acima do limite ("+itoa(latency)+" ms)"
	default:
		res.Status = StatusUp
	}
	return res
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// classify converte erros de rede em categorias genéricas (nunca expõe IPs/URLs internos).
func classify(err error) string {
	var dnsErr *net.DNSError
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var nerr net.Error
	switch {
	case errors.Is(err, ssrf.ErrBlocked):
		return "destino bloqueado pela política de segurança"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()):
		return "tempo limite excedido"
	case errors.As(err, &dnsErr):
		return "falha de resolução DNS"
	case errors.As(err, &certErr), errors.As(err, &hostErr), errors.As(err, &invalidErr):
		return "certificado TLS inválido"
	case errors.Is(err, context.Canceled):
		return "verificação cancelada"
	default:
		return "falha de conexão"
	}
}
