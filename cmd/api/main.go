package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"sentinela/internal/alerts"
	"sentinela/internal/audit"
	"sentinela/internal/auth"
	"sentinela/internal/config"
	"sentinela/internal/database"
	"sentinela/internal/events"
	apphttp "sentinela/internal/http"
	"sentinela/internal/ipintel"
	"sentinela/internal/logstore"
	"sentinela/internal/notifications"
	"sentinela/internal/retention"
	"sentinela/internal/scheduler"
	"sentinela/internal/secrets"
	"sentinela/internal/servers"
	"sentinela/internal/telemetry"
	"sentinela/internal/users"
	"sentinela/migrations"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuração inválida: %w", err)
	}
	log := telemetry.NewLogger(os.Stdout, cfg.Env, cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBMinConns)
	if err != nil {
		return err
	}
	defer pool.Close()

	migrator, err := database.NewMigrator(pool, migrations.FS)
	if err != nil {
		return err
	}

	authSvc := apphttp.NewAuthService(cfg, pool, log)
	if len(args) > 0 {
		return runCommand(ctx, log, migrator, authSvc, args)
	}

	if cfg.AutoMigrate {
		n, err := migrator.Up(ctx)
		if err != nil {
			return err
		}
		log.Info("migrações aplicadas", "count", n)
	}

	metrics := telemetry.NewMetrics()
	metrics.RegisterPool(pool)

	// Canal Telegram definido por variáveis de ambiente (token armazenado cifrado).
	var box *secrets.Box
	if cfg.SecretsKey != nil {
		if box, err = secrets.NewBox(cfg.SecretsKey); err != nil {
			return err
		}
	}
	channels := notifications.NewChannelRepository(pool, box, cfg.TelegramAllowedChatIDs)
	if err := channels.UpsertFromEnv(ctx, cfg.TelegramBotToken, cfg.TelegramChatID); err != nil {
		return fmt.Errorf("canal Telegram do ambiente: %w", err)
	}
	if cfg.SecretsKey == nil {
		log.Warn("SECRETS_KEY não configurada: canais de notificação não podem ser criados")
	}
	if cfg.AdminAPIKey != "" {
		log.Warn("ADMIN_API_KEY ativa: credencial de automação com papel admin (sem 2º fator). Em produção prefira deixá-la vazia.")
	}
	if cfg.BootstrapEmail != "" {
		created, err := authSvc.Bootstrap(ctx, cfg.BootstrapEmail, cfg.BootstrapName, cfg.BootstrapPassword)
		var be *auth.BootstrapError
		switch {
		case errors.As(err, &be):
			return fmt.Errorf("ADMIN_BOOTSTRAP_*: %s %s", be.Problems[0].Field, be.Problems[0].Message)
		case err != nil:
			return fmt.Errorf("criar administrador inicial: %w", err)
		case created:
			log.Warn("administrador inicial criado a partir de ADMIN_BOOTSTRAP_*: REMOVA ADMIN_BOOTSTRAP_PASSWORD do ambiente", "email", cfg.BootstrapEmail)
		}
	}
	if n, err := authSvc.Users.Count(ctx); err == nil && n == 0 && cfg.AdminAPIKey == "" {
		log.Warn("nenhum usuário cadastrado: crie o primeiro administrador com `sentinela-api create-admin --email ...`")
	}

	// Tarefas em segundo plano; encerram junto com a API.
	jobCtx, stopJobs := context.WithCancel(ctx)
	var jobs sync.WaitGroup
	defer func() { stopJobs(); jobs.Wait() }()
	spawn := func(fn func()) {
		jobs.Add(1)
		go func() { defer jobs.Done(); fn() }()
	}
	spawn(func() {
		(&retention.Job{
			Pool: pool, Days: cfg.MetricsRetentionDays, Interval: cfg.RetentionInterval,
			Batch: 10000, Log: log, Metrics: metrics, EventsRetention: cfg.EventsRetention,
		}).Run(jobCtx)
	})
	worker := &notifications.Worker{
		Pool: pool, Box: box, Channels: channels, Sender: notifications.NewTelegram(cfg.TelegramAPIBase),
		Log: log, Metrics: metrics, MaxAttempts: cfg.NotificationMaxAttempts,
	}
	spawn(func() { scheduler.Loop(jobCtx, "notifications", 5*time.Second, metrics, log, worker.Tick) })

	// Limpeza periódica: sessões vencidas, tentativas de login antigas e auditoria além da retenção.
	spawn(func() {
		scheduler.Loop(jobCtx, "auth_cleanup", 10*time.Minute, metrics, log, func(c context.Context) error {
			if _, _, err := authSvc.Cleanup(c); err != nil {
				return err
			}
			if cfg.AuditRetentionDays > 0 {
				_, err := audit.Purge(c, pool, time.Now().Add(-time.Duration(cfg.AuditRetentionDays)*24*time.Hour))
				return err
			}
			return nil
		})
	})

	// Stream de eventos (SSE): escuta o PostgreSQL e distribui às conexões desta instância.
	hub := events.NewHub(cfg.DatabaseURL, pool, log, metrics)
	hub.MaxClients, hub.MaxPerIP = cfg.SSEMaxClients, cfg.SSEMaxClientsPerIP
	spawn(func() { hub.Run(jobCtx) })
	monitor := &servers.ConnectivityMonitor{Pool: pool, Timeout: cfg.AgentHeartbeatTimeout}
	spawn(func() { scheduler.Loop(jobCtx, "server_connectivity", 5*time.Second, metrics, log, monitor.Tick) })

	// Logs (ClickHouse): opcional. Se estiver fora do ar na subida, a API sobe e tenta criar o esquema de
	// 30 em 30 s; enquanto isso as rotas de logs respondem 503.
	var logStore *logstore.Store
	if cfg.ClickHouseURL != "" {
		logStore, err = logstore.New(logstore.Config{URL: cfg.ClickHouseURL, Database: cfg.ClickHouseDB,
			User: cfg.ClickHouseUser, Password: cfg.ClickHousePassword, RetentionDays: cfg.LogsRetentionDays})
		if err != nil {
			return err
		}
		spawn(func() {
			scheduler.Loop(jobCtx, "logs_schema", 30*time.Second, metrics, log, func(c context.Context) error {
				if logStore.Ready() {
					return nil
				}
				if err := logStore.Init(c); err != nil {
					return err
				}
				log.Info("armazenamento de logs pronto", "retention_days", cfg.LogsRetentionDays)
				return nil
			})
		})
	} else {
		log.Info("logs desativados (CLICKHOUSE_URL vazia)")
	}

	// Geolocalização/reputação de IPs (AbuseIPDB). Sem chave, só serve o que já está no cache.
	ipIntel := ipintel.NewService(pool, &ipintel.Client{Key: cfg.AbuseIPDBKey, MaxAge: cfg.AbuseIPDBMaxAgeDays},
		cfg.IPIntelCacheTTL, cfg.AbuseIPDBDailyLimit, log)
	if cfg.AbuseIPDBKey == "" {
		log.Info("AbuseIPDB sem chave (ABUSEIPDB_API_KEY): logs sem novas consultas de geolocalização")
	}
	spawn(func() {
		scheduler.Loop(jobCtx, "ip_intel_purge", 6*time.Hour, metrics, log, func(c context.Context) error {
			return ipintel.Purge(c, pool, 4*cfg.IPIntelCacheTTL, time.Now())
		})
	})

	// Regras automáticas: grava o catálogo no PostgreSQL e arquiva qualquer regra fora dele.
	if err := alerts.SyncCatalog(ctx, pool); err != nil {
		return fmt.Errorf("sincronizar regras de alerta: %w", err)
	}
	evaluator := &alerts.Evaluator{Pool: pool, Log: log, HeartbeatTimeout: cfg.AgentHeartbeatTimeout, Metrics: metrics}
	if logStore != nil { // métricas de sistema (OOM, inodes, NTP, certificados...) vivem no ClickHouse
		evaluator.System = logStore
		evaluator.Procs = logStore
	}
	spawn(func() {
		scheduler.Loop(jobCtx, "alert_evaluation", cfg.AlertEvaluationInterval, metrics, log, evaluator.Tick)
	})
	srv := &nethttp.Server{
		Addr: cfg.HTTPAddr,
		Handler: apphttp.NewRouter(apphttp.Deps{
			Config: cfg, Log: log, Metrics: metrics, DB: pool, Pool: pool, Hub: hub, Auth: authSvc, Logs: logStore, IPIntel: ipIntel, Version: version,
		}),
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    1 << 16,
	}

	// conexões SSE são longas: ao desligar, o hub as encerra para que Shutdown não espere o timeout
	srv.RegisterOnShutdown(hub.Close)

	errCh := make(chan error, 1)
	go func() {
		log.Info("API iniciada", "addr", cfg.HTTPAddr, "env", cfg.Env, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("encerrando", "timeout", cfg.ShutdownTimeout.String())
	}
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("encerrado com sucesso")
	return nil
}

func runCommand(ctx context.Context, log *slog.Logger, m *database.Migrator, authSvc *auth.Service, args []string) error {
	switch args[0] {
	case "migrate":
		n, err := m.Up(ctx)
		if err != nil {
			return err
		}
		v, _ := m.Version(ctx)
		log.Info("migrações concluídas", "applied", n, "version", v)
	case "migrate-down":
		n, err := m.Down(ctx, 1)
		if err != nil {
			return err
		}
		log.Info("migração revertida", "reverted", n)
	case "create-admin":
		return createAdmin(ctx, log, authSvc, args[1:])
	case "reset-password":
		return resetPassword(ctx, log, authSvc, args[1:])
	case "seed-user":
		return seedUser(ctx, log, authSvc, args[1:])
	default:
		return fmt.Errorf("comando desconhecido %q (migrate|migrate-down|create-admin|reset-password|seed-user|version)", args[0])
	}
	return nil
}

// readPassword lê a senha SEM aceitá-la como argumento (apareceria em `ps` e no histórico do shell):
// da variável SENTINELA_ADMIN_PASSWORD ou da primeira linha da entrada padrão.
func readPassword() (string, error) {
	if v := os.Getenv("SENTINELA_ADMIN_PASSWORD"); v != "" {
		return v, nil
	}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "Senha (a entrada fica visível; prefira redirecionar de um arquivo ou usar a variável): ")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("informe a senha por SENTINELA_ADMIN_PASSWORD ou pela entrada padrão")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func createAdmin(ctx context.Context, log *slog.Logger, svc *auth.Service, args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail do administrador")
	name := fs.String("name", "Administrador", "nome")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	in := users.CreateInput{Name: *name, Email: *email, Role: users.RoleAdmin, Password: pw}
	if p := in.Validate(); len(p) > 0 {
		return fmt.Errorf("dados inválidos: %s %s", p[0].Field, p[0].Message)
	}
	u, err := svc.CreateUser(ctx, audit.Context{Actor: "cli"}, in)
	if err != nil {
		return err
	}
	log.Info("administrador criado", "id", u.ID, "email", u.Email)
	return nil
}

func resetPassword(ctx context.Context, log *slog.Logger, svc *auth.Service, args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail do usuário")
	if err := fs.Parse(args); err != nil {
		return err
	}
	norm, ok := users.NormalizeEmail(*email)
	if !ok {
		return errors.New("e-mail inválido")
	}
	cred, err := svc.Users.GetCredentialsByEmail(ctx, norm)
	if err != nil {
		return err
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	in := users.UpdateInput{Password: &pw}
	if p := in.Validate(cred.User); len(p) > 0 {
		return fmt.Errorf("senha inválida: %s", p[0].Message)
	}
	_, revoked, err := svc.UpdateUser(ctx, audit.Context{Actor: "cli"}, cred.ID, in)
	if err != nil {
		return err
	}
	log.Info("senha redefinida; sessões revogadas", "email", norm, "revoked_sessions", revoked)
	return nil
}

// seedUser é idempotente: cria o usuário se o e-mail não existir; se existir, redefine a senha, o papel,
// reativa a conta, revoga as sessões e limpa o bloqueio por tentativas de login.
func seedUser(ctx context.Context, log *slog.Logger, svc *auth.Service, args []string) error {
	fs := flag.NewFlagSet("seed-user", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail do usuário")
	name := fs.String("name", "Administrador", "nome (usado só ao criar)")
	role := fs.String("role", users.RoleAdmin, "papel: viewer, operator ou admin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	norm, ok := users.NormalizeEmail(*email)
	if !ok {
		return errors.New("e-mail inválido")
	}
	pw, err := readPassword()
	if err != nil {
		return err
	}
	ac := audit.Context{Actor: "cli"}

	cred, err := svc.Users.GetCredentialsByEmail(ctx, norm)
	switch {
	case errors.Is(err, users.ErrNotFound):
		in := users.CreateInput{Name: *name, Email: norm, Role: *role, Password: pw}
		if p := in.Validate(); len(p) > 0 {
			return fmt.Errorf("dados inválidos: %s %s", p[0].Field, p[0].Message)
		}
		u, err := svc.CreateUser(ctx, ac, in)
		if err != nil {
			return err
		}
		log.Info("usuário criado", "id", u.ID, "email", u.Email, "role", u.Role)
	case err != nil:
		return err
	default:
		active := true
		in := users.UpdateInput{Password: &pw, Role: role, IsActive: &active}
		if p := in.Validate(cred.User); len(p) > 0 {
			return fmt.Errorf("dados inválidos: %s %s", p[0].Field, p[0].Message)
		}
		_, revoked, err := svc.UpdateUser(ctx, ac, cred.ID, in)
		if err != nil {
			return err
		}
		log.Info("usuário atualizado: senha redefinida e conta reativada", "email", norm, "role", *role, "revoked_sessions", revoked)
	}
	cleared, err := svc.ClearLoginAttempts(ctx, norm)
	if err != nil {
		return err
	}
	log.Info("bloqueio de login limpo", "email", norm, "attempts_removed", cleared)
	return nil
}
