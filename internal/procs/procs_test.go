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
		"curl\x00--header=Authorization: Bearer x\x00http://a/b": "curl --header=Authorization: Bearer *** http://a/b",
		// cabeçalhos HTTP sensíveis
		"curl\x00-H\x00Authorization: Bearer abc123\x00https://api": "curl -H Authorization: Bearer *** https://api",
		"curl\x00-H\x00X-Api-Key: abc123\x00https://api":            "curl -H X-Api-Key: *** https://api",
		"curl\x00-H\x00Cookie: sid=abc\x00https://api":              "curl -H Cookie: *** https://api",
		"curl\x00-H\x00Accept: application/json\x00https://api":     "curl -H Accept: application/json https://api",
		// usuário:senha
		"curl\x00-u\x00admin:s3cr3t\x00https://api":  "curl -u admin:*** https://api",
		"curl\x00-uadmin:s3cr3t\x00https://api":      "curl -uadmin:*** https://api",
		"curl\x00--user=admin:s3cr3t\x00https://api": "curl --user=admin:*** https://api",
		"curl\x00-u\x00admin\x00https://api":         "curl -u admin https://api",
		"smbclient\x00//srv/x\x00-U\x00joao%s3cr3t":  "smbclient //srv/x -U joao%***",
		// opções curtas de programas conhecidos
		"mysql\x00-uroot\x00-pS3nh4\x00db":                 "mysql -uroot -p*** db",
		"/usr/bin/mysqldump\x00-pS3nh4\x00db":              "/usr/bin/mysqldump -p*** db",
		"mysql\x00-p\x00db":                                "mysql -p db", // -p sozinho pede a senha; "db" é o banco
		"redis-cli\x00-h\x00r1\x00-a\x00S3nh4\x00ping":     "redis-cli -h r1 -a *** ping",
		"sshpass\x00-pS3nh4\x00ssh\x00host":                "sshpass -p*** ssh host",
		"sshpass\x00-p\x00S3nh4\x00ssh\x00host":            "sshpass -p *** ssh host",
		"mongosh\x00-u\x00adm\x00-p\x00S3nh4":              "mongosh -u adm -p ***",
		"sudo\x00-u\x00app\x00mysql\x00-pS3nh4":            "sudo -u app mysql -p***",
		"nginx\x00-p\x00/etc/nginx":                        "nginx -p /etc/nginx", // -p de outro programa não é senha
		"docker\x00exec\x00db\x00redis-cli\x00-a\x00S3nh4": "docker exec db redis-cli -a ***",
		// argumento com espaços (shell)
		"bash\x00-c\x00mysql -uroot -pS3nh4 db < x.sql":     "bash -c mysql -uroot -p*** db < x.sql",
		"sh\x00-c\x00curl -H 'Authorization: Bearer abc' u": "sh -c curl -H 'Authorization: Bearer *** u",
		"sh\x00-c\x00echo ok && sleep 5":                    "sh -c echo ok && sleep 5",
		// parâmetros de URL
		"app\x00https://x/cb?token=abc&page=2":                 "app https://x/cb?token=***&page=2",
		"wget\x00https://s3/o?X-Amz-Signature=ff&X-Amz-Date=1": "wget https://s3/o?X-Amz-Signature=***&X-Amz-Date=1",
		"app\x00--url=https://x/?api_key=abc":                  "app --url=https://x/?api_key=***",
	}
	for in, want := range cases {
		if got := redactCmdline([]byte(in)); got != want {
			t.Errorf("redact(%q) = %q; esperado %q", in, got, want)
		}
	}
}

// A API mascara de novo o que o agente envia (texto já unido por espaços), cobrindo agentes antigos.
func TestRedactCmdlineJoined(t *testing.T) {
	cases := map[string]string{
		"mysql -uroot -pS3nh4 db":                        "mysql -uroot -p*** db",
		"curl -H Authorization: Bearer abc123 https://a": "curl -H Authorization: Bearer *** https://a",
		"curl -H X-Api-Key: abc https://a":               "curl -H X-Api-Key: *** https://a",
		"redis-cli -a S3nh4 ping":                        "redis-cli -a *** ping",
		"app --password=*** --port=80":                   "app --password=*** --port=80", // já mascarado: idempotente
		"nginx: worker  process":                         "nginx: worker  process",       // sem segredo: texto original intacto
	}
	for in, want := range cases {
		if got := RedactCmdline(in); got != want {
			t.Errorf("RedactCmdline(%q) = %q; esperado %q", in, got, want)
		}
	}
}

func TestReportValidateRedactsCmdline(t *testing.T) {
	r := goodReport(time.Now())
	r.Processes[0].Cmdline = "mysql -uroot -pS3nh4 db"
	if p := r.Validate(time.Now()); len(p) > 0 {
		t.Fatalf("problemas: %v", p)
	}
	if got := r.Processes[0].Cmdline; strings.Contains(got, "S3nh4") {
		t.Errorf("senha não mascarada na API: %q", got)
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
