package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/audit"
	"sentinela/internal/auth"
	"sentinela/internal/http/response"
	"sentinela/internal/netutil"
	"sentinela/internal/validation"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// pathUUID lê e valida um parâmetro de rota UUID; em caso de erro já responde 400.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := chi.URLParam(r, name)
	if !uuidRe.MatchString(v) {
		response.BadRequest(w, "INVALID_ID", "Identificador inválido.")
		return "", false
	}
	return strings.ToLower(v), true
}

// auditCtx identifica o autor da ação a partir do principal autenticado (usuário ou chave de API).
func auditCtx(r *http.Request, trustProxy bool) audit.Context {
	ip := netutil.ClientIP(r, trustProxy)
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return audit.Context{Actor: p.Actor(), UserID: p.UserID, IP: ip}
	}
	return audit.Context{Actor: "anonymous", IP: ip}
}

// pagination lê page/per_page com limites; problemas são acumulados em p.
func pagination(r *http.Request, p *validation.Problems) (page, perPage int) {
	page, perPage = 1, 20
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1_000_000 {
			p.Add("page", "deve ser um inteiro >= 1")
		} else {
			page = n
		}
	}
	if v := q.Get("per_page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			p.Add("per_page", "deve ser um inteiro entre 1 e 100")
		} else {
			perPage = n
		}
	}
	return page, perPage
}

type pageMeta struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

func newPageMeta(page, perPage, total int) pageMeta {
	pages := (total + perPage - 1) / perPage
	return pageMeta{Page: page, PerPage: perPage, Total: total, TotalPages: pages}
}
