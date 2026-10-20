// Package metrics define o contrato de métricas enviadas pelo agente, sua
// validação, a persistência e o cálculo de taxas de rede.
package metrics

import (
	"fmt"
	"strings"
	"time"

	"sentinela/internal/validation"
)

const (
	// MaxFutureSkew tolera relógio do agente levemente adiantado.
	MaxFutureSkew = 2 * time.Minute
	// MaxAge rejeita amostras antigas demais (o agente não acumula fila offline).
	MaxAge   = time.Hour
	MaxDisks = 64

	maxBytes = int64(1) << 60 // sanidade: ~1 EiB
)

// Host descreve o servidor; usado no heartbeat e em cada envio de métricas.
type Host struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	Architecture  string `json:"architecture"`
	UptimeSeconds *int64 `json:"uptime_seconds"`
}

type LoadAverage struct {
	M1  float64 `json:"m1"`
	M5  float64 `json:"m5"`
	M15 float64 `json:"m15"`
}

type CPU struct {
	UsagePercent *float64     `json:"usage_percent"`
	Count        *int         `json:"count"`
	LoadAverage  *LoadAverage `json:"load_average"`
}

// Memory: used = total - available (conceito MemAvailable do Linux, que considera cache recuperável).
type Memory struct {
	TotalBytes     int64 `json:"total_bytes"`
	UsedBytes      int64 `json:"used_bytes"`
	AvailableBytes int64 `json:"available_bytes"`
	SwapTotalBytes int64 `json:"swap_total_bytes"`
	SwapUsedBytes  int64 `json:"swap_used_bytes"`
}

// Network traz contadores ACUMULADOS (não taxas).
type Network struct {
	RXBytesTotal int64 `json:"rx_bytes_total"`
	TXBytesTotal int64 `json:"tx_bytes_total"`
}

type Disk struct {
	MountPoint     string `json:"mount_point"`
	Filesystem     string `json:"filesystem"`
	TotalBytes     int64  `json:"total_bytes"`
	UsedBytes      int64  `json:"used_bytes"`
	AvailableBytes int64  `json:"available_bytes"`
}

type Payload struct {
	AgentVersion string    `json:"agent_version"`
	CollectedAt  time.Time `json:"collected_at"`
	Host         Host      `json:"host"`
	CPU          CPU       `json:"cpu"`
	Memory       Memory    `json:"memory"`
	Network      *Network  `json:"network"`
	Disks        []Disk    `json:"disks"`
}

// Heartbeat é o payload mínimo de presença.
type Heartbeat struct {
	AgentVersion string `json:"agent_version"`
	Host         Host   `json:"host"`
}

func (h *Host) validate(p *validation.Problems, prefix string) {
	f := func(n string) string { return prefix + n }
	h.Hostname = p.Text(f("hostname"), h.Hostname, 0, 253)
	h.OS = p.Text(f("os"), h.OS, 0, 100)
	h.OSVersion = p.Text(f("os_version"), h.OSVersion, 0, 100)
	h.Architecture = p.Text(f("architecture"), h.Architecture, 0, 32)
	if h.UptimeSeconds != nil && (*h.UptimeSeconds < 0 || *h.UptimeSeconds > maxBytes) {
		p.Add(f("uptime_seconds"), "valor fora do intervalo")
	}
}

func (h *Heartbeat) Validate() validation.Problems {
	var p validation.Problems
	h.AgentVersion = p.Text("agent_version", h.AgentVersion, 1, 64)
	h.Host.validate(&p, "host.")
	return p
}

func nonNeg(p *validation.Problems, field string, v int64) {
	if v < 0 || v > maxBytes {
		p.Add(field, "valor fora do intervalo")
	}
}

// Validate confere tipos, intervalos e coerência. now é o horário de recebimento (confiável).
func (pl *Payload) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	pl.AgentVersion = p.Text("agent_version", pl.AgentVersion, 1, 64)
	pl.Host.validate(&p, "host.")

	switch {
	case pl.CollectedAt.IsZero():
		p.Add("collected_at", "é obrigatório")
	case pl.CollectedAt.After(now.Add(MaxFutureSkew)):
		p.Add("collected_at", "está no futuro além do tolerado")
	case pl.CollectedAt.Before(now.Add(-MaxAge)):
		p.Add("collected_at", "é antigo demais")
	}
	pl.CollectedAt = pl.CollectedAt.UTC().Truncate(time.Millisecond)

	// CPU
	if pl.CPU.UsagePercent == nil {
		p.Add("cpu.usage_percent", "é obrigatório")
	} else if u := *pl.CPU.UsagePercent; u != u || u < 0 || u > 100 { // u != u detecta NaN
		p.Add("cpu.usage_percent", "deve estar entre 0 e 100")
	}
	if pl.CPU.Count != nil && (*pl.CPU.Count < 1 || *pl.CPU.Count > 4096) {
		p.Add("cpu.count", "deve estar entre 1 e 4096")
	}
	if la := pl.CPU.LoadAverage; la != nil {
		for name, v := range map[string]float64{"m1": la.M1, "m5": la.M5, "m15": la.M15} {
			if v != v || v < 0 || v > 1e6 {
				p.Add("cpu.load_average."+name, "valor fora do intervalo")
			}
		}
	}

	// Memória
	m := pl.Memory
	nonNeg(&p, "memory.total_bytes", m.TotalBytes)
	nonNeg(&p, "memory.used_bytes", m.UsedBytes)
	nonNeg(&p, "memory.available_bytes", m.AvailableBytes)
	nonNeg(&p, "memory.swap_total_bytes", m.SwapTotalBytes)
	nonNeg(&p, "memory.swap_used_bytes", m.SwapUsedBytes)
	if m.TotalBytes <= 0 {
		p.Add("memory.total_bytes", "deve ser maior que zero")
	}
	if m.UsedBytes > m.TotalBytes {
		p.Add("memory.used_bytes", "não pode exceder o total")
	}
	if m.AvailableBytes > m.TotalBytes {
		p.Add("memory.available_bytes", "não pode exceder o total")
	}
	if m.SwapUsedBytes > m.SwapTotalBytes {
		p.Add("memory.swap_used_bytes", "não pode exceder o total de swap")
	}

	// Rede
	if n := pl.Network; n != nil {
		nonNeg(&p, "network.rx_bytes_total", n.RXBytesTotal)
		nonNeg(&p, "network.tx_bytes_total", n.TXBytesTotal)
	}

	// Discos: sem duplicatas de ponto de montagem na mesma coleta.
	if len(pl.Disks) > MaxDisks {
		p.Add("disks", fmt.Sprintf("no máximo %d volumes", MaxDisks))
		return p
	}
	seen := make(map[string]bool, len(pl.Disks))
	for i := range pl.Disks {
		d := &pl.Disks[i]
		f := func(n string) string { return fmt.Sprintf("disks[%d].%s", i, n) }
		d.MountPoint = p.Text(f("mount_point"), d.MountPoint, 1, 255)
		d.Filesystem = p.Text(f("filesystem"), d.Filesystem, 0, 32)
		if d.MountPoint != "" && !strings.HasPrefix(d.MountPoint, "/") {
			p.Add(f("mount_point"), "deve ser um caminho absoluto")
		}
		if seen[d.MountPoint] {
			p.Add(f("mount_point"), "duplicado na mesma coleta")
		}
		seen[d.MountPoint] = true
		nonNeg(&p, f("total_bytes"), d.TotalBytes)
		nonNeg(&p, f("used_bytes"), d.UsedBytes)
		nonNeg(&p, f("available_bytes"), d.AvailableBytes)
		if d.UsedBytes > d.TotalBytes {
			p.Add(f("used_bytes"), "não pode exceder o total")
		}
		if d.AvailableBytes > d.TotalBytes {
			p.Add(f("available_bytes"), "não pode exceder o total")
		}
	}
	return p
}
