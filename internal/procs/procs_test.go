package procs

import (
	"strings"
	"testing"
	"time"
)

func TestParseStat(t *testing.T) {
	// nome com espaço e ")" no meio: o resto começa no ÚLTIMO ")"
	line := "4242 (my (weird) app) S 1 4242 4242 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 7 0 987654 1000000 250 18446744073709551615"
	r, ok := parseStat(line, 4096)
	if !ok {
		t.Fatal("não leu")
	}
	if r.PID != 4242 || r.Name != "my (weird) app" || r.PPID != 1 || r.State != "S" || r.Threads != 7 {
		t.Errorf("campos: %+v", r)
	}
	if r.StartTime != 987654 || r.ticks != 200 || r.MemoryBytes != 250*4096 {
		t.Errorf("números: start=%d ticks=%d mem=%d", r.StartTime, r.ticks, r.MemoryBytes)
	}
	for _, bad := range []string{"", "1 (x) S 1", "abc (x) S 1 2 3"} {
		if _, ok := parseStat(bad, 4096); ok {
			t.Errorf("deveria recusar %q", bad)
		}
	}
}

func TestRedactCmdline(t *testing.T) {
	cases := map[string]string{
		"app\x00--password=hunter2\x00--port=80":                 "app --password=*** --port=80",
		"app\x00--password\x00hunter2\x00run":                    "app --password *** run",
		"app\x00DB_TOKEN=abc":                                    "app DB_TOKEN=***",
		"psql\x00postgres://admin:s3cr3t@db:5432/x":              "psql postgres://admin:***@db:5432/x",
		"nginx\x00-g\x00daemon off;":                             "nginx -g daemon off;",
		"curl\x00--header=Authorization: Bearer x\x00http://a/b": "curl --header=Authorization: Bearer x http://a/b",
	}
	for in, want := range cases {
		if got := redactCmdline([]byte(in)); got != want {
			t.Errorf("redact(%q) = %q; esperado %q", in, got, want)
		}
	}
}

func TestCgroupAndServiceKey(t *testing.T) {
	unit, ctr := cgroupInfo("0::/system.slice/nginx.service\n")
	if unit != "nginx.service" || ctr {
		t.Errorf("nginx: %q %v", unit, ctr)
	}
	if unit, ctr = cgroupInfo("0::/system.slice/docker-" + strings.Repeat("a", 64) + ".scope\n"); !ctr || unit != "" {
		t.Errorf("container: %q %v", unit, ctr)
	}
	if unit, ctr = cgroupInfo("0::/user.slice/user-1000.slice/session-3.scope\n"); unit != "" || ctr {
		t.Errorf("sessão: %q %v", unit, ctr)
	}
	for unit, want := range map[string]string{
		"nginx.service": "nginx", "ssh.service": "ssh", "redis@6380.service": "redis", "postgresql@16-main.service": "postgresql",
		"docker.service": "docker", "meuapp.service": "", "": "",
	} {
		if got := serviceKeyForUnit(unit); got != want {
			t.Errorf("serviceKeyForUnit(%q) = %q; esperado %q", unit, got, want)
		}
	}
}

func TestParseTarget(t *testing.T) {
	if pid, st, ok := ParseTarget("123:456"); !ok || pid != 123 || st != 456 {
		t.Errorf("válido: %d %d %v", pid, st, ok)
	}
	for _, bad := range []string{"", "123", "1:5", "0:5", "abc:5", "5:0", "5:x", "-3:5"} {
		if _, _, ok := ParseTarget(bad); ok {
			t.Errorf("deveria recusar %q", bad)
		}
	}
	if Target(10, 20) != "10:20" {
		t.Error("Target")
	}
}

func goodReport(now time.Time) Report {
	return Report{CheckedAt: now, CPUs: 4, MemoryTotalBytes: 8 << 30, Total: 2, Processes: []Process{
		{PID: 10, StartTime: 5, Name: "app", State: "S", CPUPercent: 12.5, MemoryBytes: 1 << 20, Restriction: ""},
		{PID: 11, StartTime: 6, Name: "nginx", State: "S", ServiceKey: "nginx", Restriction: RestrictService},
	}}
}

func TestReportValidate(t *testing.T) {
	now := time.Now()
	r := goodReport(now)
	r.Processes[0].ServiceName, r.Processes[0].Actions = "injetado", []string{"kill"} // campos da API são ignorados
	if p := r.Validate(now); len(p) > 0 {
		t.Fatalf("válido: %v", p)
	}
	if r.Processes[0].ServiceName != "" || r.Processes[0].Actions != nil {
		t.Error("campos da API não foram limpos")
	}
	r.Decorate()
	if r.Processes[0].MemoryPercent != 0 || len(r.Processes[0].Actions) != 2 || len(r.Processes[1].Actions) != 0 ||
		r.Processes[1].ServiceName != "Nginx" || r.Processes[1].Message == "" {
		t.Errorf("Decorate: %+v", r.Processes)
	}

	bad := map[string]func(*Report){
		"pid duplicado":    func(r *Report) { r.Processes[1].PID = 10 },
		"pid zero":         func(r *Report) { r.Processes[0].PID = 0 },
		"nome vazio":       func(r *Report) { r.Processes[0].Name = " " },
		"estado":           func(r *Report) { r.Processes[0].State = "?" },
		"serviço":          func(r *Report) { r.Processes[0].ServiceKey = "x" },
		"restrição":        func(r *Report) { r.Processes[0].Restriction = "todos" },
		"cpu negativo":     func(r *Report) { r.Processes[0].CPUPercent = -1 },
		"memória negativa": func(r *Report) { r.Processes[0].MemoryBytes = -1 },
		"cpus":             func(r *Report) { r.CPUs = 0 },
		"futuro":           func(r *Report) { r.CheckedAt = now.Add(time.Hour) },
		"demais":           func(r *Report) { r.Processes = make([]Process, MaxProcesses+1) },
	}
	for name, mut := range bad {
		r := goodReport(now)
		mut(&r)
		if p := r.Validate(now); len(p) == 0 {
			t.Errorf("%s: deveria ser recusado", name)
		}
	}
	// CPU acima do máximo (cpus*100) é limitado
	r = goodReport(now)
	r.Processes[0].CPUPercent = 9999
	r.Validate(now)
	if r.Processes[0].CPUPercent != 400 {
		t.Errorf("cpu: %v", r.Processes[0].CPUPercent)
	}
}

func TestTopSamplesAndCulprits(t *testing.T) {
	now := time.Now().UTC()
	r := Report{CheckedAt: now, Processes: []Process{
		{PID: 1, Name: "node", User: "app", CPUPercent: 80, MemoryBytes: 100 << 20},
		{PID: 2, Name: "postgres", User: "pg", CPUPercent: 5, MemoryBytes: 900 << 20},
		{PID: 3, Name: "postgres", User: "pg", CPUPercent: 4, MemoryBytes: 300 << 20},
		{PID: 4, Name: "idle", CPUPercent: 0, MemoryBytes: 1 << 20},
		{PID: 5, Name: "nginx", User: "www", CPUPercent: 2, MemoryBytes: 20 << 20},
	}}
	got := r.TopSamples(2)
	pids := map[int]bool{}
	for _, s := range got {
		pids[s.PID] = true
		if !s.At.Equal(now) {
			t.Errorf("instante: %v", s.At)
		}
	}
	// 2 maiores CPU (1, 2) + 2 maiores memória (2, 3): sem repetir
	if len(got) != 3 || !pids[1] || !pids[2] || !pids[3] {
		t.Errorf("TopSamples: %+v", got)
	}
	if (Report{}).TopSamples(5) != nil {
		t.Error("relatório vazio")
	}

	cpu := CulpritsFromSnapshot(r, KindCPU, 2)
	if cpu.Source != "snapshot" || len(cpu.Processes) != 2 || cpu.Processes[0].Name != "node" || cpu.Processes[1].Name != "postgres" || cpu.Processes[1].CPUPercent != 9 {
		t.Errorf("cpu: %+v", cpu)
	}
	if txt := cpu.Text(); txt != "Maiores consumidores de CPU (na última leitura): node 80.0% de CPU, postgres 9.0% de CPU." {
		t.Errorf("texto cpu: %q", txt)
	}
	mem := CulpritsFromSnapshot(r, KindMemory, 1)
	if mem.Processes[0].Name != "postgres" || mem.Processes[0].MemoryBytes != 1200<<20 {
		t.Errorf("memória soma os workers: %+v", mem)
	}
	mem.Source, mem.WindowSeconds = "history", 300
	if txt := mem.Text(); txt != "Maiores consumidores de memória (média dos últimos 5 min): postgres 1.2 GB." {
		t.Errorf("texto memória: %q", txt)
	}
	if (Culprits{Kind: KindCPU, Processes: []Culprit{{Name: "x", CPUPercent: 0.1}}}).Text() != "" {
		t.Error("consumo irrelevante não deve virar texto")
	}
}
