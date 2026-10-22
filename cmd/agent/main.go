// Agente do Sentinela: coleta métricas locais e as envia à API central.
// Não executa comandos recebidos da API; apenas lê /proc e statfs e faz requisições de saída.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sentinela/internal/agentclient"
	"sentinela/internal/collector"
	"sentinela/internal/discovery"
	"sentinela/internal/logtail"
	"sentinela/internal/metrics"
	"sentinela/internal/sysmetrics"
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
	disc := newDiscoveryRunner(log, client)
	sys := newSystemRunner(log, client)
	logsDone := startLogShipper(ctx, log, cfg)
	defer func() { stop(); <-logsDone }() // garante que a posição dos logs foi gravada antes de sair
	if remote := fetchCollectInterval(ctx, log, client); cfg.interval == 0 && remote > 0 {
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
		disc.runDue(ctx)
		sys.runDue(ctx)
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

// fetchCollectInterval busca em /agent/config o intervalo de coleta sugerido pela API (0 se indisponível).
func fetchCollectInterval(ctx context.Context, log *slog.Logger, client *agentclient.Client) int {
	var remote struct {
		CollectIntervalSeconds int `json:"collect_interval_seconds"`
	}
	if err := client.Do(ctx, "GET", "/api/v1/agent/config", nil, &remote); err != nil {
		logRejection(log, err)
		return 0
	}
	return remote.CollectIntervalSeconds
}

// discoveryRunner descobre sozinho os serviços do sistema (ssh, cron, nginx, redis, postgresql...)
// e envia o retrato a /agent/discovery quando algo muda — ou, no mínimo, a cada discoveryResend,
// para a API saber que a informação continua atual. Nada precisa ser cadastrado.
type discoveryRunner struct {
	log        *slog.Logger
	client     *agentclient.Client
	discoverer *collector.Discoverer
	lastCheck  time.Time
	lastSent   time.Time
	lastKey    string
}

const (
	discoveryEvery  = time.Minute
	discoveryResend = 5 * time.Minute
)

func newDiscoveryRunner(log *slog.Logger, c *agentclient.Client) *discoveryRunner {
	return &discoveryRunner{log: log, client: c, discoverer: collector.NewDiscoverer()}
}

func (r *discoveryRunner) runDue(ctx context.Context) {
	now := time.Now()
	if now.Sub(r.lastCheck) < discoveryEvery {
		return
	}
	r.lastCheck = now
	found := r.discoverer.Discover()
	var sb strings.Builder
	for _, f := range found {
		sb.WriteString(f.Key + "|" + f.Status + "|" + f.Source + "|" + f.Unit + ";")
	}
	key := sb.String()
	if key == r.lastKey && now.Sub(r.lastSent) < discoveryResend {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rep := discovery.Report{CheckedAt: now.UTC(), Services: found}
	if err := r.client.Do(sctx, "POST", "/api/v1/agent/discovery", rep, nil); err != nil {
		logRejection(r.log, err)
		r.log.Warn("envio da descoberta de serviços falhou", "err", err)
		return
	}
	r.lastKey, r.lastSent = key, now
}

// systemRunner coleta a cada minuto as métricas de sistema (OOM Killer, inodes, latência de disco, NTP,
// atualizações de segurança, certificados) e as envia a /agent/system-metrics, que as grava no ClickHouse.
// Sem ClickHouse (503) ou com falha de rede, a amostra é descartada: a próxima rodada traz dados novos.
type systemRunner struct {
	log       *slog.Logger
	client    *agentclient.Client
	collector *collector.SystemCollector
	lastRun   time.Time
}

const systemEvery = time.Minute

func newSystemRunner(log *slog.Logger, c *agentclient.Client) *systemRunner {
	return &systemRunner{log: log, client: c, collector: collector.NewSystemCollector()}
}

func (r *systemRunner) runDue(ctx context.Context) {
	now := time.Now()
	if now.Sub(r.lastRun) < systemEvery {
		return
	}
	r.lastRun = now
	samples := r.collector.Collect(now)
	if len(samples) == 0 {
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return
	}
	body := sysmetrics.Batch{BatchID: hex.EncodeToString(id[:]), Samples: samples}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := r.client.Do(sctx, "POST", "/api/v1/agent/system-metrics", body, nil); err != nil {
		logRejection(r.log, err)
		r.log.Warn("envio de métricas de sistema falhou; amostra descartada", "err", err)
		return
	}
	r.log.Debug("métricas de sistema enviadas", "samples", len(samples))
}
