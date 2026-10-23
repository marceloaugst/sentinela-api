// Agente do Sentinela: coleta métricas locais e as envia à API central.
// Só faz requisições de saída. A única coisa que executa a pedido da API são os comandos de serviço
// (iniciar, parar, reiniciar), restritos a `systemctl` sobre as unidades do catálogo (veja o pacote svcctl),
// e iniciar/reiniciar containers Docker pelo socket, se o agente tiver acesso a ele (pacote dockerhost), e encerrar
// processos do MESMO usuário do agente (pacote procs).
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
	"sentinela/internal/dockerhost"
	"sentinela/internal/logtail"
	"sentinela/internal/metrics"
	"sentinela/internal/procs"
	"sentinela/internal/svcactions"
	"sentinela/internal/svcctl"
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
	dock := newDockerRunner(log, client)
	sys := newSystemRunner(log, client)
	scanner := procs.NewScanner()
	scanner.Scan(time.Now()) // amostra-base do CPU% dos processos
	prc := newProcessRunner(log, client, scanner)
	logsDone := startLogShipper(ctx, log, cfg)
	defer func() { stop(); <-logsDone }() // garante que a posição dos logs foi gravada antes de sair
	cmdsDone := startCommandRunner(ctx, log, cfg, scanner)
	defer func() { stop(); <-cmdsDone }()
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
		hot := collectAndSend(ctx, log, col, client, interval)
		disc.runDue(ctx)
		dock.runDue(ctx)
		sys.runDue(ctx)
		prc.runDue(ctx, hot)
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

// collectAndSend coleta e envia as métricas. Devolve true se CPU ou memória estão acima de hotPercent: o laço principal
// então envia também os processos na hora, para o alerta e o histórico saberem quem estava consumindo.
func collectAndSend(ctx context.Context, log *slog.Logger, col *collector.Collector, client *agentclient.Client, interval time.Duration) bool {
	// O envio inteiro (com retentativas) não pode ultrapassar o intervalo: evita acúmulo.
	sctx, cancel := context.WithTimeout(ctx, interval)
	defer cancel()

	cctx, ccancel := context.WithTimeout(sctx, 5*time.Second)
	p, err := col.Collect(cctx, time.Now())
	ccancel()
	if err != nil {
		log.Warn("coleta descartada", "err", err)
		return false
	}
	var res struct {
		Stored    bool `json:"stored"`
		Duplicate bool `json:"duplicate"`
	}
	if err := client.Do(sctx, "POST", "/api/v1/agent/metrics", p, &res); err != nil {
		logRejection(log, err)
		log.Warn("envio de métricas falhou; amostra descartada", "err", err)
		return isHot(p)
	}
	log.Debug("métricas enviadas", "stored", res.Stored)
	return isHot(p)
}

// hotPercent é o uso de CPU ou memória a partir do qual os processos passam a ser enviados a cada coleta.
const hotPercent = 85.0

func isHot(p metrics.Payload) bool {
	if p.CPU.UsagePercent != nil && *p.CPU.UsagePercent >= hotPercent {
		return true
	}
	return p.Memory.TotalBytes > 0 && float64(p.Memory.UsedBytes)/float64(p.Memory.TotalBytes)*100 >= hotPercent
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

// dockerRunner detecta o Docker do host e lista os containers (com o erro e o fim do log dos que não estão ativos).
// O retrato vai a /agent/docker quando algo muda — ou, no mínimo, a cada dockerResend. Sem Docker, o agente
// informa isso uma vez (not_installed) e continua verificando a cada minuto, caso ele seja instalado depois.
type dockerRunner struct {
	log       *slog.Logger
	client    *agentclient.Client
	docker    *dockerhost.Client
	lastCheck time.Time
	lastSent  time.Time
	lastKey   string
}

const (
	dockerEvery  = time.Minute
	dockerResend = 5 * time.Minute
)

func newDockerRunner(log *slog.Logger, c *agentclient.Client) *dockerRunner {
	return &dockerRunner{log: log, client: c, docker: dockerhost.NewClient(os.Getenv("SENTINELA_DOCKER_SOCKET"))}
}

func (r *dockerRunner) runDue(ctx context.Context) {
	now := time.Now()
	if now.Sub(r.lastCheck) < dockerEvery {
		return
	}
	r.lastCheck = now
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	rep := r.docker.Snapshot(dctx, now)
	cancel()
	var sb strings.Builder
	sb.WriteString(rep.Status + "|" + rep.Message + ";")
	for _, c := range rep.Containers {
		code := ""
		if c.ExitCode != nil {
			code = strconv.Itoa(*c.ExitCode)
		}
		sb.WriteString(c.ID + "|" + c.State + "|" + code + "|" + c.Error + "|" + c.LogTail + ";")
	}
	key := sb.String()
	if key == r.lastKey && now.Sub(r.lastSent) < dockerResend {
		return
	}
	sctx, scancel := context.WithTimeout(ctx, 15*time.Second)
	defer scancel()
	if err := r.client.Do(sctx, "POST", "/api/v1/agent/docker", rep, nil); err != nil {
		logRejection(r.log, err)
		r.log.Warn("envio do retrato do Docker falhou", "err", err)
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

// processRunner envia a cada processEvery o retrato dos processos (CPU% e memória) a /agent/processes. O CPU% é a
// diferença entre duas leituras do /proc, por isso o Scanner é compartilhado com o executor de comandos.
type processRunner struct {
	log     *slog.Logger
	client  *agentclient.Client
	scanner *procs.Scanner
	lastRun time.Time
}

const (
	processEvery    = 30 * time.Second
	processHotEvery = 10 * time.Second
)

func newProcessRunner(log *slog.Logger, c *agentclient.Client, sc *procs.Scanner) *processRunner {
	return &processRunner{log: log, client: c, scanner: sc}
}

// runDue envia o retrato se passou processEvery — ou, com o servidor "quente" (CPU/memória altas), se passou
// processHotEvery, para registrar quem estava consumindo durante o pico.
func (r *processRunner) runDue(ctx context.Context, hot bool) {
	now := time.Now()
	every := processEvery
	if hot {
		every = processHotEvery
	}
	if now.Sub(r.lastRun) < every {
		return
	}
	r.lastRun = now
	rep := r.scanner.Scan(now)
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := r.client.Do(sctx, "POST", "/api/v1/agent/processes", rep, nil); err != nil {
		logRejection(r.log, err)
		r.log.Warn("envio dos processos falhou; amostra descartada", "err", err)
		return
	}
	r.log.Debug("processos enviados", "listed", len(rep.Processes), "total", rep.Total)
}

// commandEvery é o intervalo da busca de comandos de serviço: curto, para o botão responder rápido.
// São 12 requisições por minuto, bem abaixo do limite de 2/s por credencial.
const commandEvery = 5 * time.Second

// startCommandRunner busca na API os comandos de serviço pendentes (iniciar, parar, reiniciar), executa
// e devolve o resultado. Depois de cada comando reenvia a descoberta, para a tela refletir o novo estado.
// O canal devolvido é fechado quando o laço termina.
func startCommandRunner(ctx context.Context, log *slog.Logger, cfg settings, scanner *procs.Scanner) <-chan struct{} {
	done := make(chan struct{})
	client := agentclient.New(cfg.apiURL, cfg.token, "sentinela-agent/"+version)
	client.MaxAttempts = 2
	exec := svcctl.New(scanner)
	disc := newDiscoveryRunner(log, client)
	dock := newDockerRunner(log, client)
	go func() {
		defer close(done)
		t := time.NewTicker(commandEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			var pending []svcactions.Pending
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := client.Do(pctx, "GET", "/api/v1/agent/commands", nil, &pending)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					logRejection(log, err)
					log.Debug("busca de comandos falhou", "err", err)
				}
				continue
			}
			for _, c := range pending {
				runCommand(ctx, log, client, exec, c)
				// força o reenvio da descoberta e do retrato do Docker, para a tela refletir o novo estado
				disc.lastCheck, disc.lastKey = time.Time{}, ""
				disc.runDue(ctx)
				dock.lastCheck, dock.lastKey = time.Time{}, ""
				dock.runDue(ctx)
			}
		}
	}()
	return done
}

func runCommand(ctx context.Context, log *slog.Logger, client *agentclient.Client, exec *svcctl.Executor, c svcactions.Pending) {
	log.Info("executando comando de serviço", "id", c.ID, "service", c.ServiceKey, "action", c.Action, "target", c.Target)
	var status, msg string
	switch {
	case c.ServiceKey == procs.ServiceKey:
		status, msg = exec.ExecuteProcess(ctx, c.Target, c.Action)
	case c.Target != "":
		status, msg = exec.ExecuteContainer(ctx, c.Target, c.Action)
	default:
		status, msg = exec.Execute(ctx, c.ServiceKey, c.Action)
	}
	log.Info("comando de serviço concluído", "id", c.ID, "status", status, "message", msg)
	// O resultado é gravado mesmo durante o desligamento do agente (ele pode ter derrubado o nginx da própria API,
	// por isso com mais tentativas e prazo próprio).
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancel()
	rc := *client
	rc.MaxAttempts = 6
	if err := rc.Do(rctx, "POST", "/api/v1/agent/commands/"+c.ID+"/result", svcactions.Result{Status: status, Message: msg}, nil); err != nil {
		log.Warn("envio do resultado do comando falhou", "id", c.ID, "err", err)
	}
}
