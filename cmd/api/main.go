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
	"sentinela/internal/notifications"
	"sentinela/internal/retention"
	"sentinela/internal/scheduler"
	"sentinela/internal/secrets"
	"sentinela/internal/servers"
	"sentinela/internal/services"
	"sentinela/internal/ssrf"
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
	runner := &services.Runner{
		Repo: services.NewRepository(pool), Log: log,
		Checker: services.NewChecker(ssrf.Policy{Allowed: cfg.ServiceCheckAllowed}),
	}
	spawn(func() { scheduler.Loop(jobCtx, "service_checks", 5*time.Second, metrics, log, runner.Tick) })
	evaluator := &alerts.Evaluator{Pool: pool, Log: log, HeartbeatTimeout: cfg.AgentHeartbeatTimeout, Metrics: metrics}
	spawn(func() {
		scheduler.Loop(jobCtx, "alert_evaluation", cfg.AlertEvaluationInterval, metrics, log, evaluator.Tick)
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

	srv := &nethttp.Server{
		Addr: cfg.HTTPAddr,
		Handler: apphttp.NewRouter(apphttp.Deps{
			Config: cfg, Log: log, Metrics: metrics, DB: pool, Pool: pool, Hub: hub, Auth: authSvc, Version: version,
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
	default:
		return fmt.Errorf("comando desconhecido %q (migrate|migrate-down|create-admin|reset-password|version)", args[0])
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
