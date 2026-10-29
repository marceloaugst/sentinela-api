package handlers

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"

	"sentinela/internal/http/response"
	"sentinela/internal/logstore"
	"sentinela/internal/validation"
)

const maxCountryIPs = 1000 // IPs mais ativos considerados; o restante entra em "unknown"

type countryOut struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Events   int64  `json:"events"`
	IPs      int    `json:"ips"`
	AvgScore int    `json:"avgScore"`
}

type countriesOut struct {
	GeneratedAt string       `json:"generatedAt"`
	PeriodDays  int          `json:"periodDays"`
	Metric      string       `json:"metric"`
	Total       int64        `json:"total"`
	Countries   []countryOut `json:"countries"`
	// Unknown agrupa o que não tem país: IPs privados, ainda não consultados e os fora dos mais ativos.
	Unknown struct {
		Events int64 `json:"events"`
		IPs    int   `json:"ips"`
	} `json:"unknown"`
}

// Countries agrega a atividade dos logs por país de origem (AbuseIPDB).
func (h *Logs) Countries(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var p validation.Problems
	q := r.URL.Query()
	days := 7
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 31 {
			p.Add("days", "deve ser um inteiro entre 1 e 31")
		} else {
			days = n
		}
	}
	metric := "events"
	if v := q.Get("metric"); v != "" {
		if !logstore.ValidMetric(v) {
			p.Add("metric", "deve ser events, bans, blocks ou http_errors")
		}
		metric = v
	}
	var f logstore.Filter
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		f.ServerID = v
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	now := h.now().UTC()
	f.To, f.From = now.Add(time.Second), now.AddDate(0, 0, -days)

	ips, total, err := h.Store.IPTotals(r.Context(), f, metric, maxCountryIPs)
	if err != nil {
		h.Log.Error("falha ao agregar logs por país", "err", err)
		response.Internal(w)
		return
	}
	list := make([]string, len(ips))
	for i, t := range ips {
		list[i] = t.IP
	}
	info := h.geo(r.Context(), list)

	out := countriesOut{GeneratedAt: now.Format(time.RFC3339), PeriodDays: days, Metric: metric, Total: total, Countries: []countryOut{}}
	type acc struct {
		events int64
		ips    int
		score  int
	}
	byCode := map[string]*acc{}
	var counted int64
	for _, t := range ips {
		in, ok := info[t.IP]
		if !ok || in.Private || in.CountryCode == "" {
			out.Unknown.IPs++
			out.Unknown.Events += t.Count
			counted += t.Count
			continue
		}
		a := byCode[in.CountryCode]
		if a == nil {
			a = &acc{}
			byCode[in.CountryCode] = a
		}
		a.events += t.Count
		a.ips++
		a.score += in.AbuseScore
		counted += t.Count
	}
	out.Unknown.Events += total - counted // IPs fora do limite
	for code, a := range byCode {
		out.Countries = append(out.Countries, countryOut{Code: code, Name: countryName(code), Events: a.events,
			IPs: a.ips, AvgScore: int(float64(a.score)/float64(a.ips) + 0.5)})
	}
	sort.Slice(out.Countries, func(i, j int) bool {
		if out.Countries[i].Events != out.Countries[j].Events {
			return out.Countries[i].Events > out.Countries[j].Events
		}
		return out.Countries[i].Code < out.Countries[j].Code
	})
	response.JSON(w, http.StatusOK, out, nil)
}

func countryName(code string) string {
	reg, err := language.ParseRegion(code)
	if err != nil {
		return code
	}
	if n := display.English.Regions().Name(reg); n != "" {
		return n
	}
	return code
}
