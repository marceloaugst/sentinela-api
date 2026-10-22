package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sentinela/internal/discovery"
)

// Discoverer procura no host os serviços do catálogo. Só LÊ /proc, cgroup e arquivos de unit:
// não executa comandos e não usa o socket do Docker (que equivale a acesso root). Os caminhos são
// campos para os testes poderem apontar para uma árvore falsa.
type Discoverer struct {
	CgroupRoot string   // "/sys/fs/cgroup"
	ProcRoot   string   // "/proc"
	UnitDirs   []string // onde ficam os arquivos .service/.socket
	UFWConf    string   // "/etc/ufw/ufw.conf"
}

func NewDiscoverer() *Discoverer {
	return &Discoverer{
		CgroupRoot: "/sys/fs/cgroup",
		ProcRoot:   "/proc",
		UnitDirs:   []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"},
		UFWConf:    "/etc/ufw/ufw.conf",
	}
}

// snapshot reúne uma vez por rodada o que é caro de obter (varredura de /proc, portas, cgroups).
type snapshot struct {
	running   map[string]bool // nomes de unidades com cgroup ativo em system.slice
	procs     map[string][]proc
	listening map[int]bool
	// dockerPorts: portas de container publicadas via docker-proxy
	dockerPorts map[int]bool
}

type proc struct{ inDocker bool }

// Discover devolve um fato por item do catálogo, na ordem do catálogo.
func (d *Discoverer) Discover() []discovery.Finding {
	snap := d.snapshot()
	out := make([]discovery.Finding, 0, len(discovery.Catalog))
	for _, spec := range discovery.Catalog {
		out = append(out, d.find(spec, snap))
	}
	return out
}

func (d *Discoverer) find(spec discovery.Spec, snap snapshot) discovery.Finding {
	f := discovery.Finding{Key: spec.Key, Status: discovery.StatusNotFound}
	installed, unitName := d.installedUnit(spec.Units)

	// O UFW é "oneshot" (não deixa processo nem cgroup): vale o ENABLED do ufw.conf.
	if spec.Key == "ufw" {
		switch {
		case !installed:
			return f
		case d.ufwEnabled():
			return discovery.Finding{Key: spec.Key, Status: discovery.StatusAvailable, Source: discovery.SourceSystemd, Unit: unitName}
		}
		return discovery.Finding{Key: spec.Key, Status: discovery.StatusStopped, Unit: unitName}
	}

	// 1. Unidade systemd em execução (cgroup próprio em system.slice).
	if unit, ok := matchUnit(spec.Units, snap.running); ok {
		return discovery.Finding{Key: spec.Key, Status: discovery.StatusAvailable, Source: discovery.SourceSystemd, Unit: unit}
	}

	// 2. Processo do serviço no host ou em container.
	var host, container bool
	for _, name := range spec.Procs {
		for _, p := range snap.procs[name] {
			if p.inDocker {
				container = true
			} else {
				host = true
			}
		}
	}
	if host {
		return discovery.Finding{Key: spec.Key, Status: discovery.StatusAvailable, Source: discovery.SourceProcess, Unit: unitName}
	}
	if container && spec.DockerPort > 0 {
		return discovery.Finding{Key: spec.Key, Status: discovery.StatusAvailable, Source: discovery.SourceDocker}
	}

	// 3. Ativação por socket (ex.: ssh.socket): a unidade existe e a porta está em escuta.
	if installed {
		for _, port := range spec.Ports {
			if snap.listening[port] {
				return discovery.Finding{Key: spec.Key, Status: discovery.StatusAvailable, Source: discovery.SourceSystemd, Unit: unitName}
			}
		}
	}
	// 4. Container com a porta do serviço publicada (docker-proxy), mesmo sem ver o processo.
	if spec.DockerPort > 0 && snap.dockerPorts[spec.DockerPort] {
		return discovery.Finding{Key: spec.Key, Status: discovery.StatusAvailable, Source: discovery.SourceDocker}
	}
	if installed {
		f.Status, f.Unit = discovery.StatusStopped, unitName
	}
	return f
}

func (d *Discoverer) ufwEnabled() bool {
	b, err := os.ReadFile(d.UFWConf)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "ENABLED" {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "yes")
		}
	}
	return false
}

func (d *Discoverer) snapshot() snapshot {
	s := snapshot{running: map[string]bool{}, procs: map[string][]proc{}, listening: map[int]bool{}, dockerPorts: map[int]bool{}}
	if ents, err := os.ReadDir(filepath.Join(d.CgroupRoot, "system.slice")); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				s.running[e.Name()] = true
			}
		}
	}
	d.scanProcs(&s)
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		for p := range listeningPorts(filepath.Join(d.ProcRoot, f)) {
			s.listening[p] = true
		}
	}
	return s
}

func (d *Discoverer) scanProcs(s *snapshot) {
	ents, err := os.ReadDir(d.ProcRoot)
	if err != nil {
		return
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(d.ProcRoot, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			continue // processo encerrou durante a varredura
		}
		comm := strings.TrimSpace(string(b))
		switch comm {
		case "docker-proxy":
			if port := dockerProxyContainerPort(filepath.Join(dir, "cmdline")); port > 0 {
				s.dockerPorts[port] = true
			}
		default:
			if wanted(comm) {
				s.procs[comm] = append(s.procs[comm], proc{inDocker: inDockerCgroup(filepath.Join(dir, "cgroup"))})
			}
		}
	}
}

// wanted evita guardar processos que nenhum item do catálogo procura.
func wanted(comm string) bool {
	for _, spec := range discovery.Catalog {
		for _, p := range spec.Procs {
			if p == comm {
				return true
			}
		}
	}
	return false
}

func inDockerCgroup(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	t := string(b)
	return strings.Contains(t, "/docker/") || (strings.Contains(t, "docker-") && strings.Contains(t, ".scope"))
}

// dockerProxyContainerPort lê "-container-port N" da linha de comando do docker-proxy
// (argumentos separados por NUL).
func dockerProxyContainerPort(cmdline string) int {
	b, err := os.ReadFile(cmdline)
	if err != nil {
		return 0
	}
	args := strings.Split(string(b), "\x00")
	for i, a := range args {
		if a == "-container-port" && i+1 < len(args) {
			if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 && n <= 65535 {
				return n
			}
		}
	}
	return 0
}

// listeningPorts devolve as portas TCP em estado LISTEN (0A) de /proc/net/tcp{,6}.
func listeningPorts(path string) map[int]bool {
	out := map[int]bool{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // cabeçalho
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		i := strings.LastIndex(fields[1], ":")
		if i < 0 {
			continue
		}
		if p, err := strconv.ParseUint(fields[1][i+1:], 16, 16); err == nil {
			out[int(p)] = true
		}
	}
	return out
}

// matchUnit procura, entre as unidades do catálogo, uma que esteja nos cgroups ativos.
// Padrões terminados em "*" casam por prefixo (instâncias como postgresql@16-main.service).
func matchUnit(patterns []string, set map[string]bool) (string, bool) {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			for name := range set {
				if strings.HasPrefix(name, prefix) {
					return name, true
				}
			}
		} else if set[p] {
			return p, true
		}
	}
	return "", false
}

// installedUnit informa se algum arquivo de unit do catálogo existe e qual é o nome.
func (d *Discoverer) installedUnit(patterns []string) (bool, string) {
	for _, p := range patterns {
		prefix, glob := strings.CutSuffix(p, "*")
		for _, dir := range d.UnitDirs {
			if !glob {
				if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
					return true, p
				}
				continue
			}
			ents, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range ents {
				// "nome@.service" é só o modelo das instâncias, não um serviço instalado.
				if strings.HasPrefix(e.Name(), prefix) && !strings.HasPrefix(e.Name(), prefix+".") {
					return true, e.Name()
				}
			}
		}
	}
	return false, ""
}
