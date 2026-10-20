package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"sentinela/internal/alerts"
	"sentinela/internal/http/response"
	"sentinela/internal/validation"
)

type Alerts struct {
	Repo       *alerts.Repository
	Log        *slog.Logger
	TrustProxy bool
}

func (h Alerts) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alerts.ErrRuleNotFound), errors.Is(err, alerts.ErrAlertNotFound):
		response.NotFound(w)
	case errors.Is(err, alerts.ErrServerNotFound):
		var p validation.Problems
		p.Add("server_id", "servidor não encontrado")
		response.Validation(w, p)
	case errors.Is(err, alerts.ErrInvalidState):
		response.Error(w, http.StatusConflict, "INVALID_STATE", "O estado atual do alerta não permite esta operação.")
	default:
		h.Log.Error("erro em handler de alertas", "err", err)
		response.Internal(w)
	}
}

// ---- regras ----

func (h Alerts) ListRules(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, per := pagination(r, &p)
	q := r.URL.Query()
	lp := alerts.RuleListParams{Page: page, PerPage: per, MetricName: q.Get("metric_name"), Severity: q.Get("severity")}
	if v := q.Get("server_id"); v != "" {
		if !uuidRe.MatchString(v) {
			p.Add("server_id", "deve ser um UUID")
		}
		lp.ServerID = strings.ToLower(v)
	}
	if v := q.Get("enabled"); v != "" {
		switch v {
		case "true":
			t := true
			lp.Enabled = &t
		case "false":
			f := false
			lp.Enabled = &f
		default:
			p.Add("enabled", "deve ser true ou false")
		}
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Repo.ListRules(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(page, per, total))
}

func (h Alerts) CreateRule(w http.ResponseWriter, r *http.Request) {
	var in alerts.CreateRuleInput
	if !response.Decode(w, r, &in) {
		return
	}
	rule, p := in.Validate()
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	out, err := h.Repo.CreateRule(r.Context(), auditCtx(r, h.TrustProxy), rule)
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/alert-rules/"+out.ID)
	response.JSON(w, http.StatusCreated, out, nil)
}

func (h Alerts) GetRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	out, err := h.Repo.GetRule(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, out, nil)
}

func (h Alerts) UpdateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in alerts.UpdateRuleInput
	if !response.Decode(w, r, &in) {
		return
	}
	cur, err := h.Repo.GetRule(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	next, p := in.Validate(cur)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	out, err := h.Repo.UpdateRule(r.Context(), auditCtx(r, h.TrustProxy), next)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, out, nil)
}

func (h Alerts) DeleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.Repo.DeleteRule(r.Context(), auditCtx(r, h.TrustProxy), id); err != nil {
		h.fail(w, err)
		return
	}
	response.NoContent(w)
}

// ---- alertas ----

func parseTimeParam(p *validation.Problems, r *http.Request, name string) *time.Time {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		p.Add(name, "deve estar no formato RFC 3339")
		return nil
	}
	t = t.UTC()
	return &t
}

func (h Alerts) ListAlerts(w http.ResponseWriter, r *http.Request) {
	var p validation.Problems
	page, per := pagination(r, &p)
	q := r.URL.Query()
	lp := alerts.AlertListParams{Page: page, PerPage: per, Severity: q.Get("severity")}
	switch v := q.Get("status"); v {
	case "", "active", "firing", "acknowledged", "resolved": // pending é interno (ainda não é um alerta)
		lp.Status = v
	default:
		p.Add("status", "deve ser active, firing, acknowledged ou resolved")
	}
	switch lp.Severity {
	case "", "info", "warning", "critical":
	default:
		p.Add("severity", "deve ser info, warning ou critical")
	}
	for name, dst := range map[string]*string{"server_id": &lp.ServerID, "rule_id": &lp.RuleID} {
		if v := q.Get(name); v != "" {
			if !uuidRe.MatchString(v) {
				p.Add(name, "deve ser um UUID")
			}
			*dst = strings.ToLower(v)
		}
	}
	lp.From, lp.To = parseTimeParam(&p, r, "from"), parseTimeParam(&p, r, "to")
	if lp.From != nil && lp.To != nil && !lp.From.Before(*lp.To) {
		p.Add("from", "deve ser anterior a 'to'")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	list, total, err := h.Repo.ListAlerts(r.Context(), lp)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, list, newPageMeta(page, per, total))
}

func (h Alerts) GetAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.Repo.GetAlert(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, a, nil)
}

type ackInput struct {
	Note string `json:"note"`
}

func (h Alerts) Acknowledge(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in ackInput
	if r.ContentLength != 0 && !response.Decode(w, r, &in) {
		return
	}
	var p validation.Problems
	in.Note = p.Text("note", in.Note, 0, 500)
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	a, err := h.Repo.Acknowledge(r.Context(), auditCtx(r, h.TrustProxy), id, in.Note)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, a, nil)
}

func (h Alerts) Resolve(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.Repo.ResolveManual(r.Context(), auditCtx(r, h.TrustProxy), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	response.JSON(w, http.StatusOK, a, nil)
}
