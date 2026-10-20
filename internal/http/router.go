// Package http monta o roteador da API.
package http

import (
	"log/slog"
	nethttp "net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/agents"
	"sentinela/internal/alerts"
	"sentinela/internal/audit"
	"sentinela/internal/auth"
	"sentinela/internal/config"
	"sentinela/internal/dashboard"
	"sentinela/internal/events"
	"sentinela/internal/http/handlers"
	"sentinela/internal/http/middleware"
	"sentinela/internal/http/response"
	"sentinela/internal/incidents"
	"sentinela/internal/metrics"
	"sentinela/internal/notifications"
	"sentinela/internal/passwords"
	"sentinela/internal/ratelimit"
	"sentinela/internal/secrets"
	"sentinela/internal/servers"
	"sentinela/internal/services"
	"sentinela/internal/ssrf"
	"sentinela/internal/telemetry"
	"sentinela/internal/users"
)

// RouteInfo descreve uma rota registrada e o papel mínimo exigido. É a FONTE ÚNICA da matriz de
// autorização: o roteador a usa para proteger as rotas e os testes a usam para verificar cada uma.
type RouteInfo struct {
	Method string
	Path   string
	Role   auth.Role // vazio = pública (login) ou autenticação própria (agentes)
	Kind   string    // "public" | "user" | "agent"
}

// Registry coleta as rotas registradas (opcional; usado em testes).
type Registry struct {
	mu     sync.Mutex
	Routes []RouteInfo
}

// Mu expõe o mutex para leitura segura de Routes (testes).
func (g *Registry) Mu() *sync.Mutex { return &g.mu }

func (g *Registry) add(ri RouteInfo) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.Routes = append(g.Routes, ri)
	g.mu.Unlock()
}

type Deps struct {
	Config  config.Config
	Log     *slog.Logger
	Metrics *telemetry.Metrics
	DB      handlers.Pinger
	// Pool habilita as rotas /api/v1. Pode ser nil em testes que só exercitam a infraestrutura.
	Pool *pgxpool.Pool
	// Hub habilita GET /api/v1/events (SSE). Pode ser nil em testes.
	Hub *events.Hub
	// Auth é opcional: se nil, é criado a partir da configuração.
	Auth     *auth.Service
	Registry *Registry
	Version  string
}

// NewAuthService monta o serviço de autenticação a partir da configuração.
func NewAuthService(cfg config.Config, pool *pgxpool.Pool, log *slog.Logger) *auth.Service {
	h := passwords.NewHasher(passwords.Params{MemoryKiB: cfg.Argon2MemoryKiB, Time: cfg.Argon2Time, Threads: cfg.Argon2Threads}, 4)
	return auth.NewService(auth.Config{
		AbsoluteTTL: cfg.SessionAbsoluteTTL, IdleTTL: cfg.SessionIdleTTL,
		LockWindow: cfg.LoginLockWindow, MaxFailuresPair: cfg.LoginMaxFailures,
		MaxFailuresIP: cfg.LoginMaxFailures * 4, MaxFailuresEmail: cfg.LoginMaxFailures * 6,
		CookieSecure: cfg.CookieSecure, SameSite: sameSite(cfg.CookieSameSite), APIKey: cfg.AdminAPIKey, AllowedOrigins: cfg.CORSAllowedOrigins,
	}, pool, users.NewRepository(pool), h, log)
}

func sameSite(s string) nethttp.SameSite {
	switch s {
	case "strict":
		return nethttp.SameSiteStrictMode
	case "none":
		return nethttp.SameSiteNoneMode
	}
	return nethttp.SameSiteLaxMode
}

func NewRouter(d Deps) nethttp.Handler {
	cfg := d.Config
	r := chi.NewRouter()
	r.Use(
		middleware.RequestID,
		middleware.Recover(d.Log, d.Metrics),
		middleware.Observe(d.Log, d.Metrics),
		middleware.SecurityHeaders(cfg.IsProduction()),
		middleware.CORS(cfg.CORSAllowedOrigins),
	)
	r.NotFound(func(w nethttp.ResponseWriter, _ *nethttp.Request) { response.NotFound(w) })
	r.MethodNotAllowed(func(w nethttp.ResponseWriter, _ *nethttp.Request) { response.MethodNotAllowed(w) })

	authSvc := d.Auth
	if authSvc == nil && d.Pool != nil {
		authSvc = NewAuthService(cfg, d.Pool, d.Log)
	}

	// Rotas "normais": limite de corpo e timeout por requisição.
	r.Group(func(r chi.Router) {
		r.Use(middleware.BodyLimit(cfg.MaxBodyBytes), middleware.Timeout(cfg.RequestTimeout))

		health := handlers.Health{DB: d.DB, Version: d.Version}
		r.Get("/healthz", health.Healthz)
		r.Get("/readyz", health.Readyz)
		// /metrics: métricas internas da API. Com METRICS_TOKEN exige Bearer; mesmo assim restrinja no proxy.
		r.With(middleware.BearerToken(cfg.MetricsToken)).Method(nethttp.MethodGet, "/metrics", d.Metrics.Handler())

		if d.Pool != nil {
			r.Route("/api/v1", func(r chi.Router) { mountV1(r, d, authSvc) })
		}
	})

	// O stream SSE fica FORA do grupo acima: uma conexão longa não pode sofrer o timeout por requisição.
	// Autenticação por sessão (cookie, funciona com EventSource) ou chave de API; revalidada a cada ping.
	if d.Pool != nil && d.Hub != nil {
		r.Group(func(r chi.Router) {
			r.Use(middleware.NoStore, authSvc.Authenticate, auth.Require(auth.Viewer))
			eh := handlers.Events{Hub: d.Hub, Log: d.Log, TrustProxy: cfg.TrustProxy,
				Heartbeat: cfg.SSEHeartbeat, ReplayLimit: 1000, Valid: authSvc.SessionValid}
			r.Get("/api/v1/events", eh.Stream)
			d.Registry.add(RouteInfo{Method: "GET", Path: "/api/v1/events", Role: auth.Viewer, Kind: "user"})
		})
	}
	return r
}

func mountV1(r chi.Router, d Deps, authSvc *auth.Service) {
	cfg := d.Config
	srvRepo := servers.NewRepository(d.Pool, cfg.AgentHeartbeatTimeout)
	credRepo := agents.NewRepository(d.Pool)
	metRepo := metrics.NewRepository(d.Pool)
	dashRepo := dashboard.NewRepository(d.Pool, cfg.AgentHeartbeatTimeout)
	svcRepo := services.NewRepository(d.Pool)
	alertRepo := alerts.NewRepository(d.Pool)
	incRepo := incidents.NewRepository(d.Pool)
	policy := ssrf.Policy{Allowed: cfg.ServiceCheckAllowed}
	runner := &services.Runner{Repo: svcRepo, Checker: services.NewChecker(policy), Log: d.Log}
	var box *secrets.Box
	if cfg.SecretsKey != nil {
		var err error
		if box, err = secrets.NewBox(cfg.SecretsKey); err != nil {
			d.Log.Error("SECRETS_KEY inválida", "err", err)
		}
	}
	chRepo := notifications.NewChannelRepository(d.Pool, box, cfg.TelegramAllowedChatIDs)

	sh := handlers.Servers{Repo: srvRepo, Creds: credRepo, Log: d.Log, TrustProxy: cfg.TrustProxy}
	svh := handlers.Services{Repo: svcRepo, Servers: srvRepo, Validator: services.Validator{Policy: policy}, Runner: runner, Log: d.Log, TrustProxy: cfg.TrustProxy}
	alh := handlers.Alerts{Repo: alertRepo, Log: d.Log, TrustProxy: cfg.TrustProxy}
	inh := handlers.Incidents{Repo: incRepo, Servers: srvRepo, Log: d.Log}
	chh := handlers.Channels{Repo: chRepo, Log: d.Log, TrustProxy: cfg.TrustProxy}
	dh := handlers.Dashboard{Dash: dashRepo, Servers: srvRepo, Metrics: metRepo, Log: d.Log}
	ah := handlers.Auth{Svc: authSvc, Log: d.Log, TrustProxy: cfg.TrustProxy}
	uh := handlers.Users{Svc: authSvc, Log: d.Log, TrustProxy: cfg.TrustProxy}
	auh := handlers.AuditLogs{Log: d.Log, List: func(r *nethttp.Request, p audit.ListParams) ([]audit.Entry, int, error) {
		return audit.List(r.Context(), d.Pool, p)
	}}

	// Respostas da API nunca são guardadas em cache e há um limite de taxa por IP.
	apiLimiter := ratelimit.New(float64(cfg.APIRateLimit), cfg.APIRateBurst)
	loginLimiter := ratelimit.New(5, 10) // cada tentativa de login custa CPU/memória (Argon2id)
	r.Use(middleware.NoStore, middleware.RateLimit(apiLimiter, cfg.TrustProxy))

	// ---- pública: login (corpo pequeno e limite de taxa próprio, mais estrito) ----
	r.With(middleware.BodyLimit(8<<10), middleware.RateLimit(loginLimiter, cfg.TrustProxy)).Post("/auth/login", ah.Login)
	d.Registry.add(RouteInfo{Method: "POST", Path: "/api/v1/auth/login", Kind: "public"})

	// ---- autenticadas: cada rota declara o papel mínimo ----
	r.Group(func(r chi.Router) {
		r.Use(authSvc.Authenticate)
		route := func(method, pattern string, role auth.Role, h nethttp.HandlerFunc) {
			r.With(auth.Require(role)).MethodFunc(method, pattern, h)
			d.Registry.add(RouteInfo{Method: method, Path: "/api/v1" + pattern, Role: role, Kind: "user"})
		}
		const (
			V = auth.Viewer
			O = auth.Operator
			A = auth.Admin
		)

		// sessão
		route("GET", "/auth/me", V, ah.Me)
		route("POST", "/auth/logout", V, ah.Logout)
		route("POST", "/auth/logout-all", V, ah.LogoutAll)
		route("POST", "/auth/change-password", V, ah.ChangePassword)

		// usuários e auditoria (somente administradores)
		route("GET", "/users", A, uh.List)
		route("POST", "/users", A, uh.Create)
		route("GET", "/users/{id}", A, uh.Get)
		route("PATCH", "/users/{id}", A, uh.Update)
		route("POST", "/users/{id}/sessions/revoke", A, uh.RevokeSessions)
		route("GET", "/audit-logs", A, auh.Handle)

		// servidores e credenciais de agente
		route("GET", "/servers", V, sh.List)
		route("POST", "/servers", A, sh.Create)
		route("GET", "/servers/{id}", V, sh.Get)
		route("PATCH", "/servers/{id}", A, sh.Update)
		route("DELETE", "/servers/{id}", A, sh.Delete)
		route("GET", "/servers/{id}/disks", V, sh.Disks)
		route("GET", "/servers/{id}/summary", V, dh.ServerSummary)
		route("GET", "/servers/{id}/metrics", V, dh.ServerMetrics)
		route("GET", "/servers/{id}/services", V, svh.ListByServer)
		route("GET", "/servers/{id}/incidents", V, inh.ListByServer)
		route("GET", "/servers/{id}/agent-credentials", A, sh.ListCredentials)
		route("POST", "/servers/{id}/agent-credentials", A, sh.IssueCredential)
		route("DELETE", "/servers/{id}/agent-credentials/{credentialId}", A, sh.RevokeCredential)

		// serviços monitorados
		route("GET", "/services", V, svh.List)
		route("POST", "/services", O, svh.Create)
		route("GET", "/services/{id}", V, svh.Get)
		route("PATCH", "/services/{id}", O, svh.Update)
		route("DELETE", "/services/{id}", O, svh.Delete)
		route("POST", "/services/{id}/check", O, svh.Check)

		// regras e alertas
		route("GET", "/alert-rules", V, alh.ListRules)
		route("POST", "/alert-rules", O, alh.CreateRule)
		route("GET", "/alert-rules/{id}", V, alh.GetRule)
		route("PATCH", "/alert-rules/{id}", O, alh.UpdateRule)
		route("DELETE", "/alert-rules/{id}", O, alh.DeleteRule)
		route("GET", "/alerts", V, alh.ListAlerts)
		route("GET", "/alerts/{id}", V, alh.GetAlert)
		route("POST", "/alerts/{id}/acknowledge", O, alh.Acknowledge)
		route("POST", "/alerts/{id}/resolve", O, alh.Resolve)

		// incidentes
		route("GET", "/incidents", V, inh.List)
		route("GET", "/incidents/{id}", V, inh.Get)
		route("GET", "/incidents/{id}/events", V, inh.Events)

		// canais de notificação (contêm destinos e segredos: somente administradores)
		route("GET", "/notification-channels", A, chh.List)
		route("POST", "/notification-channels", A, chh.Create)
		route("GET", "/notification-channels/{id}", A, chh.Get)
		route("PATCH", "/notification-channels/{id}", A, chh.Update)
		route("DELETE", "/notification-channels/{id}", A, chh.Delete)
		route("POST", "/notification-channels/{id}/test", A, chh.Test)

		// dashboard
		route("GET", "/dashboard/summary", V, dh.Summary)
		route("GET", "/dashboard/metrics", V, dh.DashboardMetrics)
		route("GET", "/dashboard/recent-alerts", V, dh.RecentAlerts)
		route("GET", "/dashboard/recent-incidents", V, dh.RecentIncidents)
	})

	// ---- agentes: credencial individual + rate limiting + corpo pequeno ----
	agentAuth := agents.NewAuth(credRepo, d.Log, cfg.TrustProxy)
	if cfg.AgentRatePerSecond > 0 && cfg.AgentRateBurst > 0 { // zero => padrões do NewAuth
		agentAuth.ByCred = ratelimit.New(float64(cfg.AgentRatePerSecond), cfg.AgentRateBurst)
	}
	agh := handlers.Agent{
		Metrics: metRepo, Services: svcRepo, Log: d.Log,
		CollectInterval: cfg.AgentCollectInterval, HeartbeatTimeout: cfg.AgentHeartbeatTimeout,
		Samples: d.Metrics.Samples,
		Live:    events.NewLivePublisher(d.Pool, d.Log, 5*time.Second),
	}
	r.Route("/agent", func(r chi.Router) {
		r.Use(middleware.BodyLimit(handlers.MaxAgentBodyBytes), agentAuth.Middleware)
		for _, rt := range []struct {
			m, p string
			h    nethttp.HandlerFunc
		}{
			{"POST", "/heartbeat", agh.Heartbeat}, {"POST", "/metrics", agh.PostMetrics},
			{"POST", "/services", agh.PostServices}, {"GET", "/config", agh.Config},
		} {
			r.MethodFunc(rt.m, rt.p, rt.h)
			d.Registry.add(RouteInfo{Method: rt.m, Path: "/api/v1/agent" + rt.p, Kind: "agent"})
		}
	})
}
