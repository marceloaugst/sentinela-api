// Agente do Sentinela: coleta métricas locais e as envia à API central.
// Não executa comandos recebidos da API; apenas lê /proc e statfs e faz requisições de saída.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sentinela/internal/agentclient"
	"sentinela/internal/collector"
	"sentinela/internal/logtail"
	"sentinela/internal/metrics"
	"sentinela/internal/services"
)

var version = "dev"

const (
	defaultInterval = 15 * time.Second
	minInterval     = 5 * time.Second
	maxInterval     = 5 * time.Minute
)

type settings struct {
	apiURL        string
	token         string
	interval      time.Duration // 0 => usar o valor da API
	allowInsecure bool
}

func loadSettings(getenv func(string) string, readFile func(string) ([]byte, error)) (settings, error) {
	var s settings
	s.apiURL = strings.TrimRight(strings.TrimSpace(getenv("SENTINELA_API_URL")), "/")
	if s.apiURL == "" {
		return s, errors.New("SENTINELA_API_URL é obrigatório")
	}
	u, err := url.Parse(s.apiURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return s, errors.New("SENTINELA_API_URL inválida (use https://host)")
	}
	s.allowInsecure = getenv("SENTINELA_ALLOW_INSECURE_HTTP") == "true"
	if u.Scheme == "http" && !s.allowInsecure && !isLoopback(u.Hostname()) {
		return s, errors.New("HTTP sem TLS só é permitido para localhost; use HTTPS (ou SENTINELA_ALLOW_INSECURE_HTTP=true)")
	}

	s.token = strings.TrimSpace(getenv("SENTINELA_AGENT_TOKEN"))
	if f := getenv("SENTINELA_AGENT_TOKEN_FILE"); s.token == "" && f != "" {
		b, err := readFile(f)
		if err != nil {
			return s, fmt.Errorf("ler SENTINELA_AGENT_TOKEN_FILE: %w", err)
		}
		s.token = strings.TrimSpace(string(b))
	}
	if s.token == "" {
		return s, errors.New("defina SENTINELA_AGENT_TOKEN ou SENTINELA_AGENT_TOKEN_FILE")
	}
	if v := getenv("SENTINELA_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || time.Duration(n)*time.Second < minInterval || time.Duration(n)*time.Second > maxInterval {
			return s, errors.New("SENTINELA_INTERVAL_SECONDS deve estar entre 5 e 300")
		}
		s.interval = time.Duration(n) * time.Second
	}
	return s, nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func clampInterval(d time.Duration) time.Duration {
	switch {
	case d < minInterval:
		return minInterval
	case d > maxInterval:
		return maxInterval
	}
	return d
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("agente encerrado com erro", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadSettings(os.Getenv, os.ReadFile)
	if err != nil {
		return err
	}
	// Limites de recursos: pouca memória e uma única thread de execução Go bastam.
	debug.SetMemoryLimit(64 << 20)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := agentclient.New(cfg.apiURL, cfg.token, "sentinela-agent/"+version)
	col := collector.New(version)
	if err := col.Prime(); err != nil {
		return fmt.Errorf("inicializar coletor: %w", err)
	}

	interval := defaultInterval
	if cfg.interval > 0 {
		interval = cfg.interval
	}

	// Registro inicial: heartbeat + configuração do servidor central.
	hb := metrics.Heartbeat{AgentVersion: version, Host: col.Host()}
	if err := client.Do(ctx, "POST", "/api/v1/agent/heartbeat", hb, nil); err != nil {
		logRejection(log, err)
		log.Warn("heartbeat inicial falhou; seguindo", "err", err)
	}
	svc := newServiceRunner(log, client)
	logsDone := startLogShipper(ctx, log, cfg)
	defer func() { stop(); <-logsDone }() // garante que a posição dos logs foi gravada antes de sair
	if remote, err := svc.refresh(ctx); err == nil && cfg.interval == 0 && remote > 0 {
		interval = clampInterval(time.Duration(remote) * time.Second)
	}
	log.Info("agente iniciado", "version", version, "api", cfg.apiURL, "interval", interval.String())

	// Aguarda 1s para ter um delta de CPU significativo na primeira coleta.
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(time.Second):
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		collectAndSend(ctx, log, col, client, interval)
		svc.runDue(ctx, interval)
		select {
		case <-ctx.Done():
			log.Info("agente encerrando")
			return nil
		case <-ticker.C:
		}
	}
}

// startLogShipper inicia o envio de logs (nginx, fail2ban, ufw) se SENTINELA_LOGS estiver definida.
// O canal devolvido é fechado quando o envio termina.
func startLogShipper(ctx context.Context, log *slog.Logger, cfg settings) <-chan struct{} {
	done := make(chan struct{})
	ls, err := logtail.LoadSettings(os.Getenv)
	if err != nil {
		log.Error("configuração de logs inválida; envio de logs desativado", "err", err)
		close(done)
		return done
	}
	if len(ls.Sources) == 0 {
		close(done)
		return done
	}
	if ls.StateFile == "" {
		log.Warn("sem diretório de estado (SENTINELA_STATE_DIR/StateDirectory): a posição dos logs não sobrevive a reinícios")
	}
	// Cliente próprio: poucas tentativas por envio (o laço do Shipper já repete a cada rodada).
	lc := agentclient.New(cfg.apiURL, cfg.token, "sentinela-agent/"+version)
	lc.MaxAttempts = 2
	lc.HTTP.Timeout = 20 * time.Second
	sh := &logtail.Shipper{Sources: ls.Build(time.Local), Client: lc, Log: log}
	log.Info("envio de logs ativo", "sources", ls.Sources, "nginx_all", ls.NginxAll)
	go func() { defer close(done); sh.Run(ctx) }()
	return done
}

// logRejection destaca credencial rejeitada. O agente segue tentando a cada intervalo
// (sem loop apertado), pois o administrador pode reativar o servidor ou trocar o token.
func logRejection(log *slog.Logger, err error) {
	var perm *agentclient.PermanentError
	if errors.As(err, &perm) && perm.IsAuth() {
		log.Error("credencial rejeitada pela API (revogada, expirada ou servidor desativado)",
			"status", perm.Status, "code", perm.Code)
	}
}

func collectAndSend(ctx context.Context, log *slog.Logger, col *collector.Collector, client *agentclient.Client, interval time.Duration) {
	// O envio inteiro (com retentativas) não pode ultrapassar o intervalo: evita acúmulo.
	sctx, cancel := context.WithTimeout(ctx, interval)
	defer cancel()

	cctx, ccancel := context.WithTimeout(sctx, 5*time.Second)
	p, err := col.Collect(cctx, time.Now())
	ccancel()
	if err != nil {
		log.Warn("coleta descartada", "err", err)
		return
	}
	var res struct {
		Stored    bool `json:"stored"`
		Duplicate bool `json:"duplicate"`
	}
	if err := client.Do(sctx, "POST", "/api/v1/agent/metrics", p, &res); err != nil {
		logRejection(log, err)
		log.Warn("envio de métricas falhou; amostra descartada", "err", err)
		return
	}
	log.Debug("métricas enviadas", "stored", res.Stored)
}

// serviceRunner mantém a lista de serviços locais (vinda de /agent/config) e executa cada um no
// seu intervalo. Os resultados são enviados em lote a /agent/services.
type serviceRunner struct {
	log       *slog.Logger
	client    *agentclient.Client
	checker   *collector.ServiceChecker
	list      []services.AgentService
	lastRun   map[string]time.Time
	refreshed time.Time
}

const configRefresh = time.Minute

func newServiceRunner(log *slog.Logger, c *agentclient.Client) *serviceRunner {
	return &serviceRunner{log: log, client: c, checker: collector.NewServiceChecker(), lastRun: map[string]time.Time{}}
}

// refresh busca a configuração; devolve o intervalo de coleta sugerido pela API.
func (r *serviceRunner) refresh(ctx context.Context) (int, error) {
	var remote struct {
		CollectIntervalSeconds int                     `json:"collect_interval_seconds"`
		Services               []services.AgentService `json:"services"`
	}
	if err := r.client.Do(ctx, "GET", "/api/v1/agent/config", nil, &remote); err != nil {
		logRejection(r.log, err)
		return 0, err
	}
	r.list, r.refreshed = remote.Services, time.Now()
	return remote.CollectIntervalSeconds, nil
}

func (r *serviceRunner) runDue(ctx context.Context, interval time.Duration) {
	if time.Since(r.refreshed) >= configRefresh {
		if _, err := r.refresh(ctx); err != nil {
			r.log.Warn("não foi possível atualizar a configuração do agente", "err", err)
		}
	}
	now := time.Now()
	var due []services.AgentService
	for _, s := range r.list {
		iv := time.Duration(s.IntervalSeconds) * time.Second
		if last, ok := r.lastRun[s.ID]; !ok || now.Sub(last) >= iv-time.Second {
			due = append(due, s)
		}
	}
	if len(due) == 0 {
		return
	}
	// verificações em paralelo (limitado) para que um serviço lento não atrase os demais
	sctx, cancel := context.WithTimeout(ctx, interval)
	defer cancel()
	var (
		mu      sync.Mutex
		results []services.AgentResult
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 4)
	)
	checkedAt := time.Now().UTC()
	for _, s := range due {
		r.lastRun[s.ID] = now
		sem <- struct{}{}
		wg.Add(1)
		go func(s services.AgentService) {
			defer wg.Done()
			defer func() { <-sem }()
			if res, ok := r.checker.Check(sctx, s); ok {
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			} else {
				r.log.Warn("verificação não suportada neste host", "service", s.Name, "type", s.Type)
			}
		}(s)
	}
	wg.Wait()
	if len(results) == 0 {
		return
	}
	var out struct {
		Accepted int                 `json:"accepted"`
		Rejected []services.Rejected `json:"rejected"`
	}
	rep := services.AgentReport{CheckedAt: checkedAt, Results: results}
	if err := r.client.Do(sctx, "POST", "/api/v1/agent/services", rep, &out); err != nil {
		logRejection(r.log, err)
		r.log.Warn("envio dos resultados de serviços falhou", "err", err)
		return
	}
	if len(out.Rejected) > 0 {
		r.refreshed = time.Time{} // lista desatualizada (serviço removido?): atualiza no próximo ciclo
	}
}
