// Package config carrega e valida a configuração a partir de variáveis de ambiente.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/secrets"
)

type Config struct {
	Env         string
	HTTPAddr    string
	DatabaseURL string
	RedisURL    string

	CORSAllowedOrigins []string

	AgentHeartbeatTimeout time.Duration
	MetricsRetentionDays  int
	RetentionInterval     time.Duration

	TelegramBotToken string
	TelegramChatID   string

	DBMaxConns int32
	DBMinConns int32

	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
	RequestTimeout        time.Duration
	MaxBodyBytes          int64
	ShutdownTimeout       time.Duration

	AdminAPIKey          string // provisório até a autenticação de usuários (Fase 6)
	AgentCollectInterval time.Duration
	TrustProxy           bool // confia em X-Real-IP (só atrás de um proxy confiável)
	AgentRatePerSecond   int  // limite por credencial de agente
	AgentRateBurst       int

	// Fase 4
	SecretsKey              []byte // chave AES-256 para segredos em repouso (nil = ausente)
	TelegramAllowedChatIDs  []string
	TelegramAPIBase         string
	AlertEvaluationInterval time.Duration
	NotificationMaxAttempts int

	// Fase 5 (SSE)
	SSEHeartbeat       time.Duration
	SSEMaxClients      int
	SSEMaxClientsPerIP int
	EventsRetention    time.Duration

	// Fase 6 (autenticação e produção)
	SessionAbsoluteTTL time.Duration
	SessionIdleTTL     time.Duration
	CookieSecure       bool
	CookieSameSite     string // lax | strict | none
	LoginMaxFailures   int    // por (e-mail, IP); por IP = 4x; por e-mail = 6x
	LoginLockWindow    time.Duration
	Argon2MemoryKiB    uint32
	Argon2Time         uint32
	Argon2Threads      uint8
	APIRateLimit       int // requisições por segundo por IP
	APIRateBurst       int
	MetricsToken       string
	BootstrapEmail     string
	BootstrapName      string
	BootstrapPassword  string
	AuditRetentionDays int

	// Logs (ClickHouse). URL vazia = recurso desativado.
	ClickHouseURL      string
	ClickHouseDB       string
	ClickHouseUser     string
	ClickHousePassword string
	LogsRetentionDays  int

	AutoMigrate bool
	LogLevel    string
}

func (c Config) IsProduction() bool { return c.Env == "production" }

// Load lê a configuração usando getenv (os.Getenv em produção, mapa em testes).
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var errs []error
	str := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	integer := func(k string, def int) int {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: inteiro inválido %q", k, v))
			return def
		}
		return n
	}
	seconds := func(k string, def int) time.Duration {
		return time.Duration(integer(k, def)) * time.Second
	}
	boolean := func(k string, def bool) bool {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: booleano inválido %q", k, v))
			return def
		}
		return b
	}

	c := Config{
		Env:         str("APP_ENV", "development"),
		HTTPAddr:    str("HTTP_ADDR", ":8080"),
		DatabaseURL: str("DATABASE_URL", ""),
		RedisURL:    str("REDIS_URL", ""),

		AgentHeartbeatTimeout: seconds("AGENT_HEARTBEAT_TIMEOUT_SECONDS", 60),
		MetricsRetentionDays:  integer("METRICS_RETENTION_DAYS", 30),
		RetentionInterval:     time.Duration(integer("RETENTION_INTERVAL_MINUTES", 60)) * time.Minute,

		TelegramBotToken: str("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:   str("TELEGRAM_CHAT_ID", ""),

		DBMaxConns: int32(integer("DB_MAX_CONNS", 10)),
		DBMinConns: int32(integer("DB_MIN_CONNS", 1)),

		HTTPReadHeaderTimeout: seconds("HTTP_READ_HEADER_TIMEOUT_SECONDS", 5),
		HTTPReadTimeout:       seconds("HTTP_READ_TIMEOUT_SECONDS", 15),
		HTTPWriteTimeout:      seconds("HTTP_WRITE_TIMEOUT_SECONDS", 30),
		HTTPIdleTimeout:       seconds("HTTP_IDLE_TIMEOUT_SECONDS", 60),
		RequestTimeout:        seconds("REQUEST_TIMEOUT_SECONDS", 25),
		MaxBodyBytes:          int64(integer("MAX_BODY_BYTES", 1<<20)),
		ShutdownTimeout:       seconds("SHUTDOWN_TIMEOUT_SECONDS", 20),

		AdminAPIKey:          str("ADMIN_API_KEY", ""),
		AgentCollectInterval: seconds("AGENT_COLLECT_INTERVAL_SECONDS", 15),
		TrustProxy:           boolean("TRUST_PROXY", false),
		AgentRatePerSecond:   integer("AGENT_RATE_LIMIT_PER_SECOND", 2),
		AgentRateBurst:       integer("AGENT_RATE_LIMIT_BURST", 10),

		AutoMigrate: boolean("AUTO_MIGRATE", false),
		LogLevel:    str("LOG_LEVEL", "info"),
	}

	if k := strings.TrimSpace(getenv("SECRETS_KEY")); k != "" {
		key, err := secrets.ParseKey(k)
		if err != nil {
			errs = append(errs, err)
		}
		c.SecretsKey = key
	}
	c.TelegramAPIBase = str("TELEGRAM_API_BASE", "https://api.telegram.org")
	c.AlertEvaluationInterval = seconds("ALERT_EVALUATION_INTERVAL_SECONDS", 15)
	c.NotificationMaxAttempts = integer("NOTIFICATION_MAX_ATTEMPTS", 8)
	c.SSEHeartbeat = seconds("SSE_HEARTBEAT_SECONDS", 15)
	c.SSEMaxClients = integer("SSE_MAX_CLIENTS", 500)
	c.SSEMaxClientsPerIP = integer("SSE_MAX_CLIENTS_PER_IP", 20)
	c.EventsRetention = time.Duration(integer("EVENTS_RETENTION_HOURS", 24)) * time.Hour
	c.SessionAbsoluteTTL = time.Duration(integer("SESSION_ABSOLUTE_HOURS", 24)) * time.Hour
	c.SessionIdleTTL = time.Duration(integer("SESSION_IDLE_MINUTES", 120)) * time.Minute
	c.CookieSecure = boolean("COOKIE_SECURE", c.Env == "production")
	c.CookieSameSite = strings.ToLower(str("COOKIE_SAMESITE", "lax"))
	c.LoginMaxFailures = integer("LOGIN_MAX_FAILURES", 5)
	c.LoginLockWindow = time.Duration(integer("LOGIN_LOCK_MINUTES", 15)) * time.Minute
	c.Argon2MemoryKiB = uint32(integer("ARGON2_MEMORY_KIB", 64*1024))
	c.Argon2Time = uint32(integer("ARGON2_TIME", 3))
	c.Argon2Threads = uint8(integer("ARGON2_THREADS", 2))
	c.APIRateLimit = integer("API_RATE_LIMIT_PER_SECOND", 30)
	c.APIRateBurst = integer("API_RATE_LIMIT_BURST", 100)
	c.MetricsToken = str("METRICS_TOKEN", "")
	c.BootstrapEmail = str("ADMIN_BOOTSTRAP_EMAIL", "")
	c.BootstrapName = str("ADMIN_BOOTSTRAP_NAME", "Administrador")
	c.BootstrapPassword = getenv("ADMIN_BOOTSTRAP_PASSWORD")
	c.AuditRetentionDays = integer("AUDIT_RETENTION_DAYS", 365)
	c.ClickHouseURL = str("CLICKHOUSE_URL", "")
	c.ClickHouseDB = str("CLICKHOUSE_DB", "sentinela")
	c.ClickHouseUser = str("CLICKHOUSE_USER", "")
	c.ClickHousePassword = getenv("CLICKHOUSE_PASSWORD")
	c.LogsRetentionDays = integer("LOGS_RETENTION_DAYS", 90)
	for _, id := range strings.Split(getenv("TELEGRAM_ALLOWED_CHAT_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			c.TelegramAllowedChatIDs = append(c.TelegramAllowedChatIDs, id)
		}
	}
	// o chat configurado por variável de ambiente é, por definição, um destino autorizado
	if c.TelegramChatID != "" {
		c.TelegramAllowedChatIDs = append(c.TelegramAllowedChatIDs, c.TelegramChatID)
	}
	for _, o := range strings.Split(getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.CORSAllowedOrigins = append(c.CORSAllowedOrigins, o)
		}
	}

	if err := c.validate(); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

func (c Config) validate() error {
	var errs []error
	switch c.Env {
	case "development", "test", "production":
	default:
		errs = append(errs, fmt.Errorf("APP_ENV: valor inválido %q (development|test|production)", c.Env))
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL é obrigatório"))
	}
	if c.AgentHeartbeatTimeout < 5*time.Second {
		errs = append(errs, errors.New("AGENT_HEARTBEAT_TIMEOUT_SECONDS deve ser >= 5"))
	}
	if c.MetricsRetentionDays < 1 {
		errs = append(errs, errors.New("METRICS_RETENTION_DAYS deve ser >= 1"))
	}
	if c.TelegramBotToken != "" && c.SecretsKey == nil {
		errs = append(errs, errors.New("TELEGRAM_BOT_TOKEN exige SECRETS_KEY (o token é armazenado cifrado)"))
	}
	if c.TelegramBotToken != "" && c.TelegramChatID == "" {
		errs = append(errs, errors.New("TELEGRAM_BOT_TOKEN exige TELEGRAM_CHAT_ID"))
	}
	if u, err := url.Parse(c.TelegramAPIBase); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		errs = append(errs, errors.New("TELEGRAM_API_BASE inválida"))
	}
	if c.AlertEvaluationInterval < 5*time.Second || c.AlertEvaluationInterval > time.Hour {
		errs = append(errs, errors.New("ALERT_EVALUATION_INTERVAL_SECONDS deve estar entre 5 e 3600"))
	}
	if c.SSEHeartbeat < time.Second || c.SSEHeartbeat > 2*time.Minute {
		errs = append(errs, errors.New("SSE_HEARTBEAT_SECONDS deve estar entre 1 e 120"))
	}
	if c.SSEMaxClients < 1 || c.SSEMaxClientsPerIP < 1 {
		errs = append(errs, errors.New("SSE_MAX_CLIENTS e SSE_MAX_CLIENTS_PER_IP devem ser >= 1"))
	}
	if c.EventsRetention < time.Hour {
		errs = append(errs, errors.New("EVENTS_RETENTION_HOURS deve ser >= 1"))
	}
	switch c.CookieSameSite {
	case "lax", "strict", "none":
	default:
		errs = append(errs, errors.New("COOKIE_SAMESITE deve ser lax, strict ou none"))
	}
	if c.CookieSameSite == "none" && !c.CookieSecure {
		errs = append(errs, errors.New("COOKIE_SAMESITE=none exige COOKIE_SECURE=true"))
	}
	if c.IsProduction() && !c.CookieSecure {
		errs = append(errs, errors.New("em produção COOKIE_SECURE deve ser true (a API deve ser servida por HTTPS)"))
	}
	if c.SessionAbsoluteTTL < time.Hour || c.SessionIdleTTL < time.Minute || c.SessionIdleTTL > c.SessionAbsoluteTTL {
		errs = append(errs, errors.New("SESSION_ABSOLUTE_HOURS >= 1, SESSION_IDLE_MINUTES >= 1 e inatividade não pode exceder a duração absoluta"))
	}
	if c.LoginMaxFailures < 3 || c.LoginMaxFailures > 50 || c.LoginLockWindow < time.Minute {
		errs = append(errs, errors.New("LOGIN_MAX_FAILURES deve estar entre 3 e 50 e LOGIN_LOCK_MINUTES >= 1"))
	}
	if c.Argon2MemoryKiB < 8 || c.Argon2MemoryKiB > 512*1024 || c.Argon2Time < 1 || c.Argon2Time > 12 || c.Argon2Threads < 1 || c.Argon2Threads > 16 {
		errs = append(errs, errors.New("parâmetros ARGON2_* fora dos limites (memória 8 KiB–512 MiB, tempo 1–12, threads 1–16)"))
	}
	if c.IsProduction() && (c.Argon2MemoryKiB < 19*1024 || c.Argon2Time < 2) {
		errs = append(errs, errors.New("em produção use Argon2id com pelo menos 19 MiB e 2 iterações (recomendação OWASP)"))
	}
	if c.APIRateLimit < 1 || c.APIRateBurst < 1 {
		errs = append(errs, errors.New("API_RATE_LIMIT_PER_SECOND e API_RATE_LIMIT_BURST devem ser >= 1"))
	}
	if c.MetricsToken != "" && len(c.MetricsToken) < 16 {
		errs = append(errs, errors.New("METRICS_TOKEN deve ter pelo menos 16 caracteres"))
	}
	if (c.BootstrapEmail == "") != (c.BootstrapPassword == "") {
		errs = append(errs, errors.New("ADMIN_BOOTSTRAP_EMAIL e ADMIN_BOOTSTRAP_PASSWORD devem ser informados juntos"))
	}
	if c.AuditRetentionDays < 0 {
		errs = append(errs, errors.New("AUDIT_RETENTION_DAYS não pode ser negativo (0 = manter para sempre)"))
	}
	if c.ClickHouseURL != "" {
		if u, err := url.Parse(c.ClickHouseURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, errors.New("CLICKHOUSE_URL inválida (use http://host:8123)"))
		}
		if c.LogsRetentionDays < 1 || c.LogsRetentionDays > 3650 {
			errs = append(errs, errors.New("LOGS_RETENTION_DAYS deve estar entre 1 e 3650"))
		}
	}
	if c.NotificationMaxAttempts < 1 || c.NotificationMaxAttempts > 50 {
		errs = append(errs, errors.New("NOTIFICATION_MAX_ATTEMPTS deve estar entre 1 e 50"))
	}
	if c.RetentionInterval < time.Minute {
		errs = append(errs, errors.New("RETENTION_INTERVAL_MINUTES deve ser >= 1"))
	}
	if c.DBMaxConns < 1 || c.DBMinConns < 0 || c.DBMinConns > c.DBMaxConns {
		errs = append(errs, errors.New("DB_MAX_CONNS/DB_MIN_CONNS inconsistentes"))
	}
	if c.MaxBodyBytes < 1 {
		errs = append(errs, errors.New("MAX_BODY_BYTES deve ser > 0"))
	}
	if c.AdminAPIKey != "" && len(c.AdminAPIKey) < 32 {
		errs = append(errs, errors.New("ADMIN_API_KEY deve ter pelo menos 32 caracteres"))
	}
	if c.AgentCollectInterval < 5*time.Second || c.AgentCollectInterval > 5*time.Minute {
		errs = append(errs, errors.New("AGENT_COLLECT_INTERVAL_SECONDS deve estar entre 5 e 300"))
	}
	if c.AgentRatePerSecond < 1 || c.AgentRateBurst < 1 {
		errs = append(errs, errors.New("AGENT_RATE_LIMIT_PER_SECOND e AGENT_RATE_LIMIT_BURST devem ser >= 1"))
	}
	for _, o := range c.CORSAllowedOrigins {
		if o == "*" && c.IsProduction() {
			errs = append(errs, errors.New("CORS_ALLOWED_ORIGINS não pode ser '*' em produção"))
		}
	}
	return errors.Join(errs...)
}
