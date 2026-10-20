package services

import (
	"strings"
	"testing"
)

func problemFields(v Validator, in CreateInput) string {
	_, p := v.Create(&in)
	var sb strings.Builder
	for _, x := range p {
		sb.WriteString(x.Field + ";")
	}
	return sb.String()
}

const srv = "11111111-1111-1111-1111-111111111111"

func TestCreateValidHTTPAppliesDefaults(t *testing.T) {
	in := CreateInput{ServerID: srv, Name: " api ", Type: TypeHTTP, Target: "https://example.com/health"}
	cfg, p := Validator{}.Create(&in)
	if len(p) != 0 {
		t.Fatalf("%v", p)
	}
	if in.Name != "api" || cfg.TimeoutSeconds != 10 || cfg.IntervalSeconds != 60 || cfg.Method != "GET" ||
		len(cfg.ExpectedStatus) != 1 || cfg.ExpectedStatus[0] != 200 {
		t.Errorf("padrões: %+v", cfg)
	}
}

func TestCreateRejectsSSRFTargets(t *testing.T) {
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080", "http://localhost/admin",
		"http://10.0.0.1", "file:///etc/passwd", "http://user:pw@example.com", "http://db.internal",
	} {
		got := problemFields(Validator{}, CreateInput{ServerID: srv, Name: "x", Type: TypeHTTP, Target: target})
		if !strings.Contains(got, "target;") {
			t.Errorf("%s deveria ser rejeitado", target)
		}
	}
}

func TestCreateTCPLoopbackOnly(t *testing.T) {
	ok := []string{"127.0.0.1:5432", "localhost:6379", "[::1]:80"}
	bad := []string{"10.0.0.1:22", "example.com:443", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "127.0.0.1:abc", ":80", "169.254.169.254:80"}
	for _, tg := range ok {
		if got := problemFields(Validator{}, CreateInput{ServerID: srv, Name: "x", Type: TypeTCP, Target: tg}); got != "" {
			t.Errorf("%s: %s", tg, got)
		}
	}
	for _, tg := range bad {
		if got := problemFields(Validator{}, CreateInput{ServerID: srv, Name: "x", Type: TypeTCP, Target: tg}); !strings.Contains(got, "target;") {
			t.Errorf("%s deveria ser rejeitado", tg)
		}
	}
}

func TestCreateSystemdUnitNames(t *testing.T) {
	for _, tg := range []string{"nginx", "nginx.service", "docker.socket", "user@1000.service", "my_app-1"} {
		if got := problemFields(Validator{}, CreateInput{ServerID: srv, Name: "x", Type: TypeSystemd, Target: tg}); got != "" {
			t.Errorf("%s: %s", tg, got)
		}
	}
	for _, tg := range []string{"", "nginx; rm -rf /", "a b", "$(id)", "../../etc", "x`y`", strings.Repeat("a", 129), "a/b"} {
		if got := problemFields(Validator{}, CreateInput{ServerID: srv, Name: "x", Type: TypeSystemd, Target: tg}); !strings.Contains(got, "target;") {
			t.Errorf("%q deveria ser rejeitado (injeção de comando)", tg)
		}
	}
	if NormalizeUnit("nginx") != "nginx.service" || NormalizeUnit("docker.socket") != "docker.socket" {
		t.Error("NormalizeUnit")
	}
}

func TestCreateConfigRules(t *testing.T) {
	base := CreateInput{ServerID: srv, Name: "x", Type: TypeHTTP, Target: "https://example.com"}
	cases := map[string]Config{
		"config.timeout_seconds":  {TimeoutSeconds: 99},
		"config.interval_seconds": {IntervalSeconds: 5},
		"config.method":           {Method: "POST"},
		"config.expected_status":  {ExpectedStatus: []int{200, 700}},
		"config.body_contains":    {Method: "HEAD", BodyContains: "ok"},
		"config.max_latency_ms":   {MaxLatencyMS: -1},
	}
	for field, c := range cases {
		in := base
		cc := c
		in.Config = &cc
		if got := problemFields(Validator{}, in); !strings.Contains(got, field+";") {
			t.Errorf("%s: %q", field, got)
		}
	}
	// timeout >= intervalo
	in := base
	in.Config = &Config{TimeoutSeconds: 20, IntervalSeconds: 15}
	if got := problemFields(Validator{}, in); !strings.Contains(got, "config.timeout_seconds;") {
		t.Errorf("timeout >= intervalo: %q", got)
	}
	// campos http em serviço de agente
	in = CreateInput{ServerID: srv, Name: "x", Type: TypeSystemd, Target: "nginx", Config: &Config{ExpectedStatus: []int{200}}}
	if got := problemFields(Validator{}, in); !strings.Contains(got, "config;") {
		t.Errorf("campos http em systemd: %q", got)
	}
}

func TestCreateOtherFields(t *testing.T) {
	if got := problemFields(Validator{}, CreateInput{ServerID: "x", Name: "", Type: "ftp", Target: "t"}); !strings.Contains(got, "server_id;") ||
		!strings.Contains(got, "name;") || !strings.Contains(got, "service_type;") {
		t.Errorf("%q", got)
	}
}

func TestUpdateValidation(t *testing.T) {
	cur := Service{Type: TypeHTTP, Config: Config{TimeoutSeconds: 10, IntervalSeconds: 60, Method: "GET", ExpectedStatus: []int{200}}}
	if _, p := (Validator{}).Update(cur, &UpdateInput{}); len(p) != 1 {
		t.Errorf("patch vazio: %v", p)
	}
	bad := "http://127.0.0.1"
	if _, p := (Validator{}).Update(cur, &UpdateInput{Target: &bad}); len(p) == 0 {
		t.Error("novo alvo interno deveria ser rejeitado")
	}
	good := "https://example.org"
	cfg, p := (Validator{}).Update(cur, &UpdateInput{Target: &good})
	if len(p) != 0 || cfg.IntervalSeconds != 60 {
		t.Errorf("%v %+v", p, cfg)
	}
}

func TestSanitizeError(t *testing.T) {
	got := SanitizeError("falha\r\n\x1b[31mvermelho\x00" + strings.Repeat("x", 300))
	if strings.ContainsAny(got, "\r\n\x1b\x00") || len([]rune(got)) > 200 {
		t.Errorf("%q", got)
	}
}

func TestDefaultTimeoutAdaptsToShortIntervals(t *testing.T) {
	// o padrão (10 s) só é reduzido quando não cabe no intervalo escolhido
	for iv, want := range map[int]int{10: 5, 11: 10, 12: 10, 15: 10, 20: 10} {
		in := CreateInput{ServerID: srv, Name: "x", Type: TypeHTTP, Target: "https://example.com", Config: &Config{IntervalSeconds: iv}}
		cfg, p := Validator{}.Create(&in)
		if len(p) != 0 || cfg.TimeoutSeconds != want {
			t.Errorf("intervalo %d: timeout=%d (esperado %d) problemas=%v", iv, cfg.TimeoutSeconds, want, p)
		}
	}
	in := CreateInput{ServerID: srv, Name: "x", Type: TypeHTTP, Target: "https://example.com", Config: &Config{IntervalSeconds: 60}}
	if cfg, _ := (Validator{}).Create(&in); cfg.TimeoutSeconds != 10 {
		t.Errorf("com intervalo folgado o padrão continua 10 s: %d", cfg.TimeoutSeconds)
	}
	// timeout explícito inválido continua sendo recusado
	in = CreateInput{ServerID: srv, Name: "x", Type: TypeHTTP, Target: "https://example.com", Config: &Config{IntervalSeconds: 10, TimeoutSeconds: 10}}
	if _, p := (Validator{}).Create(&in); len(p) == 0 {
		t.Error("timeout explícito >= intervalo deve falhar")
	}
}
