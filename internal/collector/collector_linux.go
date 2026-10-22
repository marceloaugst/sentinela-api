//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"sentinela/internal/metrics"
)

// Collector lê métricas do host. Não executa comandos externos.
type Collector struct {
	procRoot     string // "/proc" (parametrizável em testes)
	osReleaseFn  string
	agentVersion string
	prevCPU      CPUTimes
	havePrev     bool
}

func New(agentVersion string) *Collector {
	return &Collector{procRoot: "/proc", osReleaseFn: "/etc/os-release", agentVersion: agentVersion}
}

func (c *Collector) read(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(c.procRoot, name))
	return string(b), err
}

// Prime registra a leitura inicial de CPU, necessária para calcular deltas.
func (c *Collector) Prime() error {
	s, err := c.read("stat")
	if err != nil {
		return err
	}
	t, err := ParseCPUStat(s)
	if err != nil {
		return err
	}
	c.prevCPU, c.havePrev = t, true
	return nil
}

// Host devolve o inventário do servidor (usado no heartbeat).
func (c *Collector) Host() metrics.Host {
	h := metrics.Host{Architecture: runtime.GOARCH}
	h.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile(c.osReleaseFn); err == nil {
		h.OS, h.OSVersion = ParseOSRelease(string(b))
	}
	if h.OS == "" {
		h.OS = runtime.GOOS
	}
	if s, err := c.read("uptime"); err == nil {
		if u, err := ParseUptime(s); err == nil {
			h.UptimeSeconds = &u
		}
	}
	return h
}

// Collect produz uma amostra completa. Falhas parciais em itens opcionais (rede,
// discos, load) não impedem o envio; falhas em CPU/memória sim.
func (c *Collector) Collect(ctx context.Context, now time.Time) (metrics.Payload, error) {
	if !c.havePrev {
		return metrics.Payload{}, errors.New("coletor não inicializado (Prime)")
	}
	p := metrics.Payload{AgentVersion: c.agentVersion, CollectedAt: now.UTC(), Host: c.Host()}

	stat, err := c.read("stat")
	if err != nil {
		return p, fmt.Errorf("cpu: %w", err)
	}
	cur, err := ParseCPUStat(stat)
	if err != nil {
		return p, err
	}
	usage, ok := CPUUsage(c.prevCPU, cur)
	if !ok {
		c.prevCPU = cur
		return p, errors.New("intervalo de CPU inválido; amostra descartada")
	}
	c.prevCPU = cur
	p.CPU.UsagePercent = &usage
	n := runtime.NumCPU()
	p.CPU.Count = &n
	if s, err := c.read("loadavg"); err == nil {
		if la, err := ParseLoadavg(s); err == nil {
			p.CPU.LoadAverage = &la
		}
	}

	mi, err := c.read("meminfo")
	if err != nil {
		return p, fmt.Errorf("memória: %w", err)
	}
	if p.Memory, err = ParseMeminfo(mi); err != nil {
		return p, err
	}

	if s, err := c.read("net/dev"); err == nil {
		if rx, tx, found := ParseNetDev(s); found {
			p.Network = &metrics.Network{RXBytesTotal: rx, TXBytesTotal: tx}
		}
	}

	if s, err := c.read("mounts"); err == nil {
		for _, m := range ParseMounts(s, metrics.MaxDisks) {
			if ctx.Err() != nil {
				return p, ctx.Err()
			}
			var st syscall.Statfs_t
			if err := syscall.Statfs(m.MountPoint, &st); err != nil {
				continue
			}
			bs := uint64(st.Bsize)
			total := st.Blocks * bs
			if total == 0 {
				continue
			}
			used := (st.Blocks - st.Bfree) * bs
			avail := st.Bavail * bs
			if used > total {
				used = total
			}
			if avail > total {
				avail = total
			}
			p.Disks = append(p.Disks, metrics.Disk{
				MountPoint: m.MountPoint, Filesystem: m.FSType,
				TotalBytes: int64(total), UsedBytes: int64(used), AvailableBytes: int64(avail),
			})
		}
	}
	return p, nil
}

type inodeInfo struct {
	mount string
	pct   float64
}

// inodeUsage calcula o percentual de inodes usados nos mesmos pontos de montagem monitorados no disco.
func inodeUsage(mounts string) []inodeInfo {
	var out []inodeInfo
	for _, m := range ParseMounts(mounts, metrics.MaxDisks) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(m.MountPoint, &st); err != nil || st.Files == 0 {
			continue // sistemas de arquivos sem inodes fixos (btrfs, xfs dinâmico...) reportam 0
		}
		out = append(out, inodeInfo{m.MountPoint, float64(st.Files-st.Ffree) / float64(st.Files) * 100})
	}
	return out
}
