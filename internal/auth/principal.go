// Package auth implementa autenticação (sessões e chave de API), autorização por papel e proteção CSRF.
package auth

import "context"

// Role: viewer < operator < admin.
type Role string

const (
	Viewer   Role = "viewer"
	Operator Role = "operator"
	Admin    Role = "admin"
)

func (r Role) Rank() int {
	switch r {
	case Viewer:
		return 1
	case Operator:
		return 2
	case Admin:
		return 3
	}
	return 0 // papel desconhecido: nenhum acesso
}

func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() && r.Rank() > 0 }

// Como a requisição se autenticou.
const (
	ViaSession = "session"
	ViaAPIKey  = "api_key"
)

// Principal é quem está fazendo a requisição.
type Principal struct {
	UserID    string // vazio para a chave de API
	Name      string
	Email     string
	Role      Role
	SessionID string
	Via       string
}

// Actor é o rótulo usado em auditoria e em eventos de incidente.
func (p Principal) Actor() string {
	if p.Via == ViaAPIKey {
		return "api_key"
	}
	return p.Email
}

type ctxKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}
