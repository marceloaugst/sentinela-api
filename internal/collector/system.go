package collector

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/sysmetrics"
)

// Parsers puros (testáveis) das métricas de sistema. Só lê arquivos: não executa comandos.

// ParseVmstatOOM devolve o contador acumulado oom_kill de /proc/vmstat (ok=false se o kernel não o expõe).
func ParseVmstatOOM(s string) (uint64, bool) {
	for _, line := range strings.Split(s, "\n") {
		k, v, found := strings.Cut(line, " ")
		if found && k == "oom_kill" {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// DiskStat são os contadores acumulados de um dispositivo em /proc/diskstats.
type DiskStat struct {
	Ops    uint64 // leituras + escritas concluídas
	TimeMS uint64 // milissegundos gastos em leituras + escritas
}

// ParseDiskstats lê /proc/diskstats mantendo só discos inteiros (sem partições, loop, ram, dm e zram).
func ParseDiskstats(s string) map[string]DiskStat {
	out := map[string]DiskStat{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 11 || !isWholeDisk(f[2]) {
			continue
		}
		n := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		// campos: 3 leituras, 6 ms lendo, 7 escritas, 10 ms escrevendo
		out[f[2]] = DiskStat{Ops: n(3) + n(7), TimeMS: n(6) + n(10)}
	}
	return out
}

var (
	partitionRe = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+)[0-9]+$|^(nvme[0-9]+n[0-9]+|mmcblk[0-9]+)p[0-9]+$`)
	diskRe      = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$`)
)

func isWholeDisk(name string) bool { return diskRe.MatchString(name) && !partitionRe.MatchString(name) }

// DiskLatencyMS é a latência média por operação entre duas leituras (ok=false sem operações novas).
func DiskLatencyMS(prev, cur DiskStat) (float64, bool) {
	if cur.Ops <= prev.Ops || cur.TimeMS < prev.TimeMS {
		return 0, false
	}
	return float64(cur.TimeMS-prev.TimeMS) / float64(cur.Ops-prev.Ops), true
}

var updatesRe = regexp.MustCompile(`(?m)^\d+\s+updates?\b`)

// ParseSecurityUpdates lê /var/lib/update-notifier/updates-available (Ubuntu/Debian com update-notifier).
// Exemplo: "12 updates can be applied immediately.\n3 of these updates are standard security updates."
func ParseSecurityUpdates(s string) (int, bool) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " of these updates are"); i > 0 && strings.Contains(line, "security") {
			if n, err := strconv.Atoi(strings.TrimSpace(line[:i])); err == nil {
				return n, true
			}
		}
	}
	if updatesRe.MatchString(s) {
		return 0, true // há aviso de atualizações, mas nenhuma de segurança
	}
	return 0, false
}

// CertDaysLeft devolve os dias até o certificado PEM vencer (negativo = já venceu).
func CertDaysLeft(pemData []byte, now time.Time) (float64, bool) {
	for len(pemData) > 0 {
		var blk *pem.Block
		blk, pemData = pem.Decode(pemData)
		if blk == nil {
			return 0, false
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return 0, false
		}
		return c.NotAfter.Sub(now).Hours() / 24, true // o primeiro é o certificado da folha
	}
	return 0, false
}

// SystemCollector reúne as métricas de sistema. Guarda o estado anterior para calcular deltas.
type SystemCollector struct {
	ProcRoot     string
	CertGlobs    []string // onde procurar certificados PEM (padrão: Let's Encrypt)
	UpdatesFile  string
	TimesyncFile string // existe quando o systemd-timesyncd sincronizou o relógio

	prevOOM  uint64
	haveOOM  bool
	prevDisk map[string]DiskStat
}

func NewSystemCollector() *SystemCollector {
	return &SystemCollector{
		ProcRoot: "/proc",
		// fullchain.pem é público, mas /etc/letsencrypt/live é 0700 do root: veja docs/alertas-automaticos.md
		CertGlobs:    []string{"/etc/sentinela/certs/*.pem", "/etc/letsencrypt/live/*/fullchain.pem"},
		UpdatesFile:  "/var/lib/update-notifier/updates-available",
		TimesyncFile: "/run/systemd/timesync/synchronized",
	}
}

func (c *SystemCollector) readProc(name string) string {
	b, _ := os.ReadFile(filepath.Join(c.ProcRoot, name))
	return string(b)
}

// Collect devolve as amostras desta rodada. Fontes ausentes (kernel, arquivo, pacote) apenas não geram amostra.
func (c *SystemCollector) Collect(now time.Time) []sysmetrics.Sample {
	var out []sysmetrics.Sample
	add := func(metric, subject string, v float64) {
		out = append(out, sysmetrics.Sample{Time: now.UTC(), Metric: metric, Subject: subject, Value: v})
	}

	if n, ok := ParseVmstatOOM(c.readProc("vmstat")); ok {
		if c.haveOOM && n >= c.prevOOM {
			add(sysmetrics.OOMKills, "", float64(n-c.prevOOM))
		}
		c.prevOOM, c.haveOOM = n, true
	}

	cur := ParseDiskstats(c.readProc("diskstats"))
	for dev, st := range cur {
		if prev, ok := c.prevDisk[dev]; ok {
			if ms, ok := DiskLatencyMS(prev, st); ok {
				add(sysmetrics.DiskLatency, dev, ms)
			}
		}
	}
	c.prevDisk = cur

	for _, ino := range inodeUsage(c.readProc("mounts")) {
		add(sysmetrics.InodeUsed, ino.mount, ino.pct)
	}

	if _, err := os.Stat(filepath.Dir(c.TimesyncFile)); err == nil { // só sabemos se o timesyncd existe
		_, err := os.Stat(c.TimesyncFile)
		if err == nil {
			add(sysmetrics.NTPUnsynced, "", 0)
		} else {
			add(sysmetrics.NTPUnsynced, "", 1)
		}
	}

	if b, err := os.ReadFile(c.UpdatesFile); err == nil {
		if n, ok := ParseSecurityUpdates(string(b)); ok {
			add(sysmetrics.SecurityUpdates, "", float64(n))
		}
	}

	for _, g := range c.CertGlobs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if d, ok := CertDaysLeft(b, now); ok {
				name := strings.TrimSuffix(filepath.Base(f), ".pem")
				if name == "fullchain" {
					name = filepath.Base(filepath.Dir(f))
				}
				add(sysmetrics.CertDaysLeft, name, d)
			}
		}
	}
	return out
}
