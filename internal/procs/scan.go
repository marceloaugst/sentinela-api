package procs

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentinela/internal/discovery"
)

const (
	clockTicks = 100 // USER_HZ: fixo em 100 no Linux
	// Quantos processos vão em cada relatório: os que mais usam CPU e os que mais usam memória.
	topByCPU      = 150
	reportMax     = 300
	maxCmdline    = 4096
	minCPUElapsed = time.Second
)

// Scanner lê /proc. É seguro para uso concorrente: o laço principal e o executor de comandos o compartilham, e
// o CPU% depende da amostra anterior.
type Scanner struct {
	Root     string // /proc (trocável em testes)
	SelfPID  int
	SelfUID  int
	PageSize int

	mu     sync.Mutex
	prev   map[int]cpuSample
	prevAt time.Time
	users  map[string]string
}

type cpuSample struct {
	start uint64
	ticks uint64
}

// NewScanner cria o leitor do /proc do host.
func NewScanner() *Scanner {
	return &Scanner{Root: "/proc", SelfPID: os.Getpid(), SelfUID: os.Getuid(), PageSize: os.Getpagesize(), users: map[string]string{}}
}

// raw é o que sai da leitura de um processo, antes do CPU%.
type raw struct {
	Process
	ticks uint64
	uid   int
}

// criticalNames nunca são encerráveis, mesmo que o agente rode como o mesmo usuário.
var criticalNames = map[string]bool{
	"init": true, "systemd": true, "sshd": true, "dockerd": true, "containerd": true, "dbus-daemon": true,
	"polkitd": true, "systemd-journal": true, "systemd-logind": true, "systemd-udevd": true, "agetty": true, "login": true,
}

// ReadProcess lê um processo. ok=false se ele não existe mais (ou é thread de kernel).
func (s *Scanner) readProcess(pid int) (raw, bool) {
	dir := filepath.Join(s.Root, strconv.Itoa(pid))
	statB, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return raw{}, false
	}
	r, ok := parseStat(string(statB), s.PageSize)
	if !ok || r.PID != pid {
		return raw{}, false
	}
	if r.PID == 2 || r.PPID == 2 {
		return raw{}, false // thread de kernel
	}
	r.uid = -1
	if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		r.uid = parseUID(string(b))
	}
	r.User = s.userName(r.uid)
	var cmd string
	if b, err := readLimited(filepath.Join(dir, "cmdline"), maxCmdline); err == nil {
		cmd = redactCmdline(b)
	}
	if cmd == "" {
		cmd = "[" + r.Name + "]"
	}
	r.Cmdline = clean(cmd, maxText)
	cg := ""
	if b, err := readLimited(filepath.Join(dir, "cgroup"), 2048); err == nil {
		cg = string(b)
	}
	r.ServiceKey, r.Restriction = s.classify(r, cg)
	return r, true
}

// classify decide a chave de serviço e a restrição. Ordem importa: do mais grave ao menos.
func (s *Scanner) classify(r raw, cgroup string) (serviceKey, restriction string) {
	unit, container := cgroupInfo(cgroup)
	serviceKey = serviceKeyForUnit(unit)
	switch {
	case r.PID == 1 || criticalNames[r.Name] || strings.HasPrefix(r.Name, "systemd"):
		restriction = RestrictCritical
	case r.PID == s.SelfPID || r.Name == "sentinela-agent":
		restriction = RestrictSelf
	case container:
		restriction = RestrictContainer
	case serviceKey != "":
		restriction = RestrictService
	case r.uid < 0 || r.uid != s.SelfUID:
		restriction = RestrictOtherUser
	}
	return
}

func (s *Scanner) userName(uid int) string {
	if uid < 0 {
		return ""
	}
	k := strconv.Itoa(uid)
	if n, ok := s.users[k]; ok {
		return n
	}
	name := k
	if u, err := user.LookupId(k); err == nil && u.Username != "" {
		name = u.Username
	}
	s.users[k] = name
	return name
}

// Scan lê todos os processos e calcula o CPU% pela diferença para a amostra anterior. Processo que apareceu depois
// dela viveu menos que a janela inteira, então todo o tempo de CPU dele conta. A primeira chamada (sem amostra anterior)
// devolve CPU% zero: use-a para "aquecer".
func (s *Scanner) Scan(now time.Time) Report {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, _ := os.ReadDir(s.Root)
	all := make([]raw, 0, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid < 1 {
			continue
		}
		if r, ok := s.readProcess(pid); ok {
			all = append(all, r)
		}
	}

	elapsed := now.Sub(s.prevAt)
	if s.prevAt.IsZero() || elapsed < 0 {
		elapsed = 0
	} else if elapsed < minCPUElapsed {
		elapsed = minCPUElapsed
	}
	for i := range all {
		r := &all[i]
		if elapsed == 0 {
			continue
		}
		delta := r.ticks
		if p, ok := s.prev[r.PID]; ok && p.start == r.StartTime && r.ticks >= p.ticks {
			delta = r.ticks - p.ticks
		}
		r.CPUPercent = round1(float64(delta) / clockTicks / elapsed.Seconds() * 100)
	}
	// Só avança a amostra-base se passou tempo suficiente: leituras seguidas medem contra a mesma base.
	if s.prevAt.IsZero() || now.Sub(s.prevAt) >= 2*minCPUElapsed {
		next := make(map[int]cpuSample, len(all))
		for _, r := range all {
			next[r.PID] = cpuSample{start: r.StartTime, ticks: r.ticks}
		}
		s.prev, s.prevAt = next, now
	}

	rep := Report{CheckedAt: now.UTC(), CPUs: runtime.NumCPU(), MemoryTotalBytes: s.memTotal(), Total: len(all)}
	rep.Processes = pick(all)
	return rep
}

// Inspect relê um processo (para conferir antes de encerrar).
func (s *Scanner) Inspect(pid int) (Process, bool) {
	r, ok := s.readProcess(pid)
	return r.Process, ok
}

// pick escolhe até reportMax processos: os de maior CPU e, para completar, os de maior memória.
func pick(all []raw) []Process {
	byCPU := make([]raw, len(all))
	copy(byCPU, all)
	sort.SliceStable(byCPU, func(i, j int) bool {
		if byCPU[i].CPUPercent != byCPU[j].CPUPercent {
			return byCPU[i].CPUPercent > byCPU[j].CPUPercent
		}
		return byCPU[i].MemoryBytes > byCPU[j].MemoryBytes
	})
	chosen := map[int]bool{}
	out := make([]Process, 0, min(len(all), reportMax))
	add := func(r raw) {
		if !chosen[r.PID] && len(out) < reportMax {
			chosen[r.PID] = true
			out = append(out, r.Process)
		}
	}
	for i := 0; i < len(byCPU) && i < topByCPU; i++ {
		add(byCPU[i])
	}
	sort.SliceStable(byCPU, func(i, j int) bool { return byCPU[i].MemoryBytes > byCPU[j].MemoryBytes })
	for _, r := range byCPU {
		add(r)
	}
	return out
}

func (s *Scanner) memTotal() int64 {
	b, err := os.ReadFile(filepath.Join(s.Root, "meminfo"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

func readLimited(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, max)
	n, err := f.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// parseStat lê /proc/<pid>/stat. O nome fica entre parênteses e pode conter espaços e ")": o resto começa depois do ÚLTIMO ")".
// Com rest = campos a partir do 3º (estado): campo n => rest[n-3].
func parseStat(s string, pageSize int) (raw, bool) {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return raw{}, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil {
		return raw{}, false
	}
	rest := strings.Fields(s[end+1:])
	if len(rest) < 22 {
		return raw{}, false
	}
	u := func(i int) uint64 { v, _ := strconv.ParseUint(rest[i], 10, 64); return v }
	ppid, _ := strconv.Atoi(rest[1])
	threads, _ := strconv.Atoi(rest[17])
	rss, _ := strconv.ParseInt(rest[21], 10, 64)
	if rss < 0 {
		rss = 0
	}
	var r raw
	r.PID, r.PPID, r.Name, r.State, r.Threads = pid, ppid, s[open+1:end], rest[0], threads
	r.StartTime = u(19)
	r.ticks = u(11) + u(12)
	r.MemoryBytes = rss * int64(pageSize)
	return r, true
}

// parseUID lê o UID real da linha "Uid:" de /proc/<pid>/status (-1 se não achar).
func parseUID(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				if v, err := strconv.Atoi(f[0]); err == nil {
					return v
				}
			}
		}
	}
	return -1
}

// cgroupInfo extrai a unidade systemd (.service) e se o processo está num container Docker, a partir de /proc/<pid>/cgroup.
func cgroupInfo(cg string) (unit string, container bool) {
	for _, line := range strings.Split(cg, "\n") {
		path := line
		if i := strings.LastIndexByte(line, ':'); i >= 0 {
			path = line[i+1:]
		}
		if strings.Contains(path, "/docker/") || strings.Contains(path, "docker-") && strings.Contains(path, ".scope") ||
			strings.Contains(path, "/kubepods") || strings.Contains(path, "libpod-") {
			container = true
		}
		for _, part := range strings.Split(path, "/") {
			if strings.HasSuffix(part, ".service") && unit == "" {
				unit = part
			}
		}
	}
	return
}

// serviceKeyForUnit devolve a chave do catálogo cuja lista de unidades casa com a unidade (vazio se nenhuma).
func serviceKeyForUnit(unit string) string {
	if unit == "" {
		return ""
	}
	for _, spec := range discovery.Catalog {
		for _, u := range spec.Units {
			if prefix, glob := strings.CutSuffix(u, "*"); glob {
				if strings.HasPrefix(unit, prefix) {
					return spec.Key
				}
			} else if u == unit || strings.TrimSuffix(u, ".socket")+".service" == unit {
				return spec.Key
			}
		}
	}
	return ""
}

var (
	secretKeyRe  = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[-_]?key|apikey|auth|credential|private[-_]?key)`)
	userinfoRe   = regexp.MustCompile(`(://[^/\s:@]+:)[^/\s@]+@`)
	flagOrAssign = regexp.MustCompile(`^(-{0,2}[A-Za-z0-9_.-]+)=(.*)$`)
)

// redactCmdline junta os argumentos (separados por NUL) mascarando o que parece segredo: "--password=x", "TOKEN=x",
// o argumento seguinte a "--password" e senhas em URLs (user:senha@host). É heurístico: reduz o vazamento, não o garante.
func redactCmdline(b []byte) string {
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	out := make([]string, 0, len(args))
	maskNext := false
	for _, a := range args {
		switch {
		case maskNext:
			a, maskNext = "***", false
		default:
			if m := flagOrAssign.FindStringSubmatch(a); m != nil && secretKeyRe.MatchString(m[1]) {
				a = m[1] + "=***"
			} else if strings.HasPrefix(a, "-") && secretKeyRe.MatchString(a) && !strings.Contains(a, "=") {
				maskNext = true
			}
			a = userinfoRe.ReplaceAllString(a, "${1}***@")
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}

func itoa(i int) string { return strconv.Itoa(i) }

// startOf devolve o início (ticks) do processo, 0 se ele não existe.
func (s *Scanner) startOf(pid int) uint64 {
	b, err := os.ReadFile(filepath.Join(s.Root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	r, ok := parseStat(string(b), s.PageSize)
	if !ok {
		return 0
	}
	return r.StartTime
}

// gone informa se o processo (pid, início) terminou: sumiu, foi substituído por outro com o mesmo pid ou virou zumbi.
func (s *Scanner) gone(pid int, start uint64) bool {
	b, err := os.ReadFile(filepath.Join(s.Root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return true
	}
	r, ok := parseStat(string(b), s.PageSize)
	return !ok || r.StartTime != start || r.State == "Z" || r.State == "X"
}
