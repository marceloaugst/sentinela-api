package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_URL": "postgres://x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != ":8080" || c.Env != "development" {
		t.Errorf("defaults inesperados: %+v", c)
	}
	if c.AgentHeartbeatTimeout != 60*time.Second || c.MetricsRetentionDays != 30 {
		t.Errorf("defaults de agente/retenção inesperados: %+v", c)
	}
}

func TestLoadCORSList(t *testing.T) {
	c, err := Load(env(map[string]string{
		"DATABASE_URL":         "postgres://x",
		"CORS_ALLOWED_ORIGINS": " https://a.com , https://b.com,, ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.CORSAllowedOrigins) != 2 || c.CORSAllowedOrigins[1] != "https://b.com" {
		t.Errorf("origens: %v", c.CORSAllowedOrigins)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"sem database":     {},
		"env inválido":     {"DATABASE_URL": "x", "APP_ENV": "staging"},
		"inteiro inválido": {"DATABASE_URL": "x", "METRICS_RETENTION_DAYS": "abc"},
		"timeout baixo":    {"DATABASE_URL": "x", "AGENT_HEARTBEAT_TIMEOUT_SECONDS": "1"},
		"cors * em prod":   {"DATABASE_URL": "x", "APP_ENV": "production", "CORS_ALLOWED_ORIGINS": "*"},
		"admin key curta":  {"DATABASE_URL": "x", "ADMIN_API_KEY": "curta"},
		"intervalo agente": {"DATABASE_URL": "x", "AGENT_COLLECT_INTERVAL_SECONDS": "1"},
		"clickhouse url":   {"DATABASE_URL": "x", "CLICKHOUSE_URL": "clickhouse:9000"},
		"retenção logs":    {"DATABASE_URL": "x", "CLICKHOUSE_URL": "http://ch:8123", "LOGS_RETENTION_DAYS": "0"},
		"rate zero":        {"DATABASE_URL": "x", "AGENT_RATE_LIMIT_PER_SECOND": "0"},
		"pool inválido":    {"DATABASE_URL": "x", "DB_MAX_CONNS": "2", "DB_MIN_CONNS": "5"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(env(m)); err == nil {
				t.Error("esperava erro")
			}
		})
	}
}

func TestLoadPhase4(t *testing.T) {
	key := strings.Repeat("ab", 32)
	c, err := Load(env(map[string]string{
		"DATABASE_URL": "x", "SECRETS_KEY": key, "TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "-100",
		"TELEGRAM_ALLOWED_CHAT_IDS": "42, 43",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SecretsKey) != 32 {
		t.Errorf("%+v", c)
	}
	// o chat do ambiente entra na lista de autorizados
	if got := strings.Join(c.TelegramAllowedChatIDs, ","); got != "42,43,-100" {
		t.Errorf("autorizados: %s", got)
	}
	if c.AlertEvaluationInterval != 15*time.Second || c.NotificationMaxAttempts != 8 || c.TelegramAPIBase != "https://api.telegram.org" {
		t.Errorf("padrões: %+v", c)
	}
	for name, m := range map[string]map[string]string{
		"token sem chave":   {"DATABASE_URL": "x", "TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1"},
		"token sem chat":    {"DATABASE_URL": "x", "TELEGRAM_BOT_TOKEN": "t", "SECRETS_KEY": key},
		"chave inválida":    {"DATABASE_URL": "x", "SECRETS_KEY": "curta"},
		"api base inválida": {"DATABASE_URL": "x", "TELEGRAM_API_BASE": "ftp://x"},
		"avaliação rápida":  {"DATABASE_URL": "x", "ALERT_EVALUATION_INTERVAL_SECONDS": "1"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: esperava erro", name)
		}
	}
}

func TestLoadPhase5(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_URL": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.SSEHeartbeat != 15*time.Second || c.SSEMaxClients != 500 || c.SSEMaxClientsPerIP != 20 || c.EventsRetention != 24*time.Hour {
		t.Errorf("padrões: %+v", c)
	}
	for name, m := range map[string]map[string]string{
		"heartbeat 0":   {"DATABASE_URL": "x", "SSE_HEARTBEAT_SECONDS": "0"},
		"heartbeat 999": {"DATABASE_URL": "x", "SSE_HEARTBEAT_SECONDS": "999"},
		"clientes 0":    {"DATABASE_URL": "x", "SSE_MAX_CLIENTS": "0"},
		"por ip 0":      {"DATABASE_URL": "x", "SSE_MAX_CLIENTS_PER_IP": "0"},
		"retenção 0":    {"DATABASE_URL": "x", "EVENTS_RETENTION_HOURS": "0"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: esperava erro", name)
		}
	}
}

func TestLoadAbuseIPDB(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_URL": "x"}))
	if err != nil || c.AbuseIPDBKey != "" || c.AbuseIPDBDailyLimit != 1000 || c.AbuseIPDBMaxAgeDays != 90 || c.IPIntelCacheTTL != 168*time.Hour {
		t.Fatalf("padrões: %+v, %v", c, err)
	}
	for name, m := range map[string]map[string]string{
		"idade 0":   {"DATABASE_URL": "x", "ABUSEIPDB_MAX_AGE_DAYS": "0"},
		"idade 400": {"DATABASE_URL": "x", "ABUSEIPDB_MAX_AGE_DAYS": "400"},
		"cache 0":   {"DATABASE_URL": "x", "IP_INTEL_CACHE_HOURS": "0"},
		"cota 0":    {"DATABASE_URL": "x", "ABUSEIPDB_DAILY_LIMIT": "0"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: esperava erro", name)
		}
	}
}

func TestLoadPhase6(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_URL": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionAbsoluteTTL != 24*time.Hour || c.SessionIdleTTL != 2*time.Hour || c.CookieSecure || c.CookieSameSite != "lax" ||
		c.LoginMaxFailures != 5 || c.Argon2MemoryKiB != 65536 || c.Argon2Time != 3 || c.APIRateLimit != 30 || c.AuditRetentionDays != 365 {
		t.Errorf("padrões: %+v", c)
	}
	// em produção o cookie é Secure por padrão
	prod, err := Load(env(map[string]string{"DATABASE_URL": "x", "APP_ENV": "production"}))
	if err != nil || !prod.CookieSecure {
		t.Errorf("produção: %v secure=%v", err, prod.CookieSecure)
	}
	for name, m := range map[string]map[string]string{
		"produção sem cookie seguro": {"DATABASE_URL": "x", "APP_ENV": "production", "COOKIE_SECURE": "false"},
		"produção com argon2 fraco":  {"DATABASE_URL": "x", "APP_ENV": "production", "ARGON2_MEMORY_KIB": "1024"},
		"samesite inválido":          {"DATABASE_URL": "x", "COOKIE_SAMESITE": "talvez"},
		"samesite none sem secure":   {"DATABASE_URL": "x", "COOKIE_SAMESITE": "none", "COOKIE_SECURE": "false"},
		"inatividade > absoluta":     {"DATABASE_URL": "x", "SESSION_ABSOLUTE_HOURS": "1", "SESSION_IDLE_MINUTES": "120"},
		"falhas de login baixas":     {"DATABASE_URL": "x", "LOGIN_MAX_FAILURES": "1"},
		"argon2 absurdo":             {"DATABASE_URL": "x", "ARGON2_MEMORY_KIB": "99999999"},
		"token de métricas curto":    {"DATABASE_URL": "x", "METRICS_TOKEN": "curto"},
		"bootstrap incompleto":       {"DATABASE_URL": "x", "ADMIN_BOOTSTRAP_EMAIL": "a@b.com"},
		"limite de api zero":         {"DATABASE_URL": "x", "API_RATE_LIMIT_PER_SECOND": "0"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: esperava erro", name)
		}
	}
	ok, err := Load(env(map[string]string{"DATABASE_URL": "x", "COOKIE_SAMESITE": "none", "COOKIE_SECURE": "true", "METRICS_TOKEN": strings.Repeat("m", 20),
		"ADMIN_BOOTSTRAP_EMAIL": "a@b.com", "ADMIN_BOOTSTRAP_PASSWORD": "uma-senha-longa-ok"}))
	if err != nil || ok.CookieSameSite != "none" || ok.BootstrapPassword == "" {
		t.Errorf("combinação válida: %v", err)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{"APP_ENV": "x"}))
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") || !strings.Contains(err.Error(), "APP_ENV") {
		t.Errorf("deveria agregar erros: %v", err)
	}
}

func TestLoadLogsConfig(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_URL": "x"}))
	if err != nil || c.ClickHouseURL != "" || c.LogsRetentionDays != 90 {
		t.Fatalf("padrão: logs desativados e 90 dias: %+v %v", c, err)
	}
	c, err = Load(env(map[string]string{"DATABASE_URL": "x", "CLICKHOUSE_URL": "http://clickhouse:8123", "CLICKHOUSE_PASSWORD": " s3 ", "LOGS_RETENTION_DAYS": "30"}))
	if err != nil || c.ClickHouseURL != "http://clickhouse:8123" || c.ClickHouseDB != "sentinela" || c.LogsRetentionDays != 30 {
		t.Fatalf("%+v %v", c, err)
	}
	if c.ClickHousePassword != " s3 " { // senhas não são "aparadas"
		t.Errorf("senha alterada: %q", c.ClickHousePassword)
	}
}
