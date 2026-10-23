package main

import (
	"errors"
	"testing"
	"time"

	"sentinela/internal/metrics"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func noFile(string) ([]byte, error) { return nil, errors.New("sem arquivo") }

func TestLoadSettings(t *testing.T) {
	ok, err := loadSettings(env(map[string]string{
		"SENTINELA_API_URL": "https://api.exemplo.com/", "SENTINELA_AGENT_TOKEN": "snt_x",
		"SENTINELA_INTERVAL_SECONDS": "30",
	}), noFile)
	if err != nil || ok.apiURL != "https://api.exemplo.com" || ok.interval != 30*time.Second {
		t.Fatalf("%+v %v", ok, err)
	}
	if _, err := loadSettings(env(map[string]string{"SENTINELA_API_URL": "http://localhost:8080", "SENTINELA_AGENT_TOKEN": "t"}), noFile); err != nil {
		t.Errorf("http em localhost deveria ser aceito: %v", err)
	}
}

func TestLoadSettingsErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"sem url":          {"SENTINELA_AGENT_TOKEN": "t"},
		"url inválida":     {"SENTINELA_API_URL": "ftp://x", "SENTINELA_AGENT_TOKEN": "t"},
		"http remoto":      {"SENTINELA_API_URL": "http://api.exemplo.com", "SENTINELA_AGENT_TOKEN": "t"},
		"sem token":        {"SENTINELA_API_URL": "https://x.com"},
		"arquivo inválido": {"SENTINELA_API_URL": "https://x.com", "SENTINELA_AGENT_TOKEN_FILE": "/nao/existe"},
		"intervalo baixo":  {"SENTINELA_API_URL": "https://x.com", "SENTINELA_AGENT_TOKEN": "t", "SENTINELA_INTERVAL_SECONDS": "1"},
	}
	for name, m := range cases {
		if _, err := loadSettings(env(m), noFile); err == nil {
			t.Errorf("%s: esperava erro", name)
		}
	}
}

func TestTokenFromFileAndInsecureOverride(t *testing.T) {
	s, err := loadSettings(env(map[string]string{
		"SENTINELA_API_URL": "http://10.0.0.5:8080", "SENTINELA_ALLOW_INSECURE_HTTP": "true",
		"SENTINELA_AGENT_TOKEN_FILE": "/etc/token",
	}), func(string) ([]byte, error) { return []byte("snt_abc\n"), nil })
	if err != nil || s.token != "snt_abc" {
		t.Errorf("%+v %v", s, err)
	}
}

func TestClampInterval(t *testing.T) {
	if clampInterval(time.Second) != minInterval || clampInterval(time.Hour) != maxInterval || clampInterval(20*time.Second) != 20*time.Second {
		t.Error("clampInterval incorreto")
	}
}

func TestIsHot(t *testing.T) {
	pct := func(v float64) *float64 { return &v }
	cases := []struct {
		name string
		p    metrics.Payload
		want bool
	}{
		{"ocioso", metrics.Payload{CPU: metrics.CPU{UsagePercent: pct(10)}, Memory: metrics.Memory{TotalBytes: 1000, UsedBytes: 300}}, false},
		{"cpu alta", metrics.Payload{CPU: metrics.CPU{UsagePercent: pct(91)}, Memory: metrics.Memory{TotalBytes: 1000, UsedBytes: 300}}, true},
		{"cpu no limite", metrics.Payload{CPU: metrics.CPU{UsagePercent: pct(85)}}, true},
		{"memória alta", metrics.Payload{CPU: metrics.CPU{UsagePercent: pct(5)}, Memory: metrics.Memory{TotalBytes: 1000, UsedBytes: 900}}, true},
		{"sem cpu medida e sem memória", metrics.Payload{}, false},
	}
	for _, c := range cases {
		if got := isHot(c.p); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
