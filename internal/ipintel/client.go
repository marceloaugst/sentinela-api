// Package ipintel consulta a reputação e a localização de IPs no AbuseIPDB, com cache no PostgreSQL.
//
// O AbuseIPDB devolve país (não coordenadas), provedor e uma pontuação de abuso. O plano gratuito permite
// 1000 consultas por dia, então o resultado é guardado e só IPs novos ou vencidos vão à rede.
package ipintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var (
	ErrRateLimited  = errors.New("ipintel: cota do AbuseIPDB esgotada")
	ErrUnauthorized = errors.New("ipintel: chave do AbuseIPDB rejeitada")
)

// Info é o que se sabe sobre um IP. Private=true quando o endereço não é público (nada foi consultado).
type Info struct {
	IP             string     `json:"-"`
	Private        bool       `json:"private,omitempty"`
	CountryCode    string     `json:"country_code,omitempty"` // ISO 3166-1 alfa-2
	ISP            string     `json:"isp,omitempty"`
	UsageType      string     `json:"usage_type,omitempty"`
	Domain         string     `json:"domain,omitempty"`
	AbuseScore     int        `json:"abuse_score"` // 0-100
	TotalReports   int        `json:"total_reports"`
	IsTor          bool       `json:"is_tor,omitempty"`
	LastReportedAt *time.Time `json:"last_reported_at,omitempty"`
	FetchedAt      time.Time  `json:"fetched_at"`
}

// Client fala com a API v2 do AbuseIPDB.
type Client struct {
	Key     string
	BaseURL string // padrão https://api.abuseipdb.com
	MaxAge  int    // janela (dias) dos relatórios considerados na pontuação
	HTTP    *http.Client
}

func (c *Client) Check(ctx context.Context, ip string, now time.Time) (Info, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://api.abuseipdb.com"
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	q := url.Values{"ipAddress": {ip}, "maxAgeInDays": {strconv.Itoa(max(c.MaxAge, 1))}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v2/check?"+q.Encode(), nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Key", c.Key)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Info{}, err
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return Info{}, ErrRateLimited
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Info{}, ErrUnauthorized
	case resp.StatusCode != http.StatusOK:
		return Info{}, fmt.Errorf("ipintel: AbuseIPDB respondeu %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			CountryCode    string     `json:"countryCode"`
			ISP            string     `json:"isp"`
			UsageType      string     `json:"usageType"`
			Domain         string     `json:"domain"`
			AbuseScore     int        `json:"abuseConfidenceScore"`
			TotalReports   int        `json:"totalReports"`
			IsTor          bool       `json:"isTor"`
			LastReportedAt *time.Time `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Info{}, fmt.Errorf("ipintel: resposta inválida: %w", err)
	}
	d := out.Data
	return Info{IP: ip, CountryCode: d.CountryCode, ISP: d.ISP, UsageType: d.UsageType, Domain: d.Domain,
		AbuseScore: d.AbuseScore, TotalReports: d.TotalReports, IsTor: d.IsTor, LastReportedAt: d.LastReportedAt, FetchedAt: now}, nil
}
