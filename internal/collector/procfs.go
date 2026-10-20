// Package collector coleta métricas locais do Linux lendo /proc e statfs.
// Os parsers são funções puras sobre texto para facilitar testes.
package collector

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"sentinela/internal/metrics"
)

// CPUTimes são contadores acumulados de /proc/stat (em jiffies).
type CPUTimes struct{ Total, Idle uint64 }

// ParseCPUStat lê a linha agregada "cpu " de /proc/stat. guest/guest_nice já estão
// contidos em user/nice e por isso ficam fora da soma.
func ParseCPUStat(s string) (CPUTimes, error) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var v [8]uint64
		for i := 0; i < 8 && i+1 < len(f); i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("cpu stat: %w", err)
			}
			v[i] = n
		}
		var total uint64
		for _, n := range v {
			total += n
		}
		return CPUTimes{Total: total, Idle: v[3] + v[4]}, nil // idle + iowait
	}
	return CPUTimes{}, errors.New("linha 'cpu' não encontrada em /proc/stat")
}

// CPUUsage calcula o percentual de uso entre duas leituras.
func CPUUsage(prev, cur CPUTimes) (float64, bool) {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0, false
	}
	dt := float64(cur.Total - prev.Total)
	di := float64(cur.Idle - prev.Idle)
	u := (dt - di) / dt * 100
	if u < 0 {
		u = 0
	}
	if u > 100 {
		u = 100
	}
	return u, true
}

// ParseMeminfo converte /proc/meminfo. "Usada" = MemTotal - MemAvailable, que desconta
// cache e buffers recuperáveis (não conta cache como memória ocupada).
func ParseMeminfo(s string) (metrics.Memory, error) {
	kv := map[string]int64{}
	for _, line := range strings.Split(s, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && strings.EqualFold(f[1], "kB") {
			n *= 1024
		}
		kv[name] = n
	}
	total, ok := kv["MemTotal"]
	if !ok || total <= 0 {
		return metrics.Memory{}, errors.New("MemTotal ausente em /proc/meminfo")
	}
	avail, ok := kv["MemAvailable"]
	if !ok { // kernels antigos: aproximação
		avail = kv["MemFree"] + kv["Buffers"] + kv["Cached"]
	}
	if avail > total {
		avail = total
	}
	m := metrics.Memory{TotalBytes: total, AvailableBytes: avail, UsedBytes: total - avail}
	m.SwapTotalBytes = kv["SwapTotal"]
	m.SwapUsedBytes = m.SwapTotalBytes - kv["SwapFree"]
	if m.SwapUsedBytes < 0 {
		m.SwapUsedBytes = 0
	}
	return m, nil
}

func ParseLoadavg(s string) (metrics.LoadAverage, error) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return metrics.LoadAverage{}, errors.New("formato inesperado em /proc/loadavg")
	}
	var v [3]float64
	for i := range v {
		n, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return metrics.LoadAverage{}, err
		}
		v[i] = n
	}
	return metrics.LoadAverage{M1: v[0], M5: v[1], M15: v[2]}, nil
}

func ParseUptime(s string) (int64, error) {
	f := strings.Fields(s)
	if len(f) < 1 {
		return 0, errors.New("formato inesperado em /proc/uptime")
	}
	n, err := strconv.ParseFloat(f[0], 64)
	if err != nil || n < 0 {
		return 0, errors.New("uptime inválido")
	}
	return int64(n), nil
}

// Interfaces virtuais/loopback são ignoradas: seus contadores aparecem e somem
// (containers, VPNs) e distorceriam o total acumulado do host.
var virtualIfacePrefixes = []string{"lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun", "tap", "wg", "tailscale"}

func isVirtualIface(name string) bool {
	for _, p := range virtualIfacePrefixes {
		if name == p || strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ParseNetDev soma bytes recebidos/enviados das interfaces físicas.
// found=false quando não há interface elegível.
func ParseNetDev(s string) (rx, tx int64, found bool) {
	for _, line := range strings.Split(s, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || isVirtualIface(name) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseInt(f[0], 10, 64)
		t, err2 := strconv.ParseInt(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx += r
		tx += t
		found = true
	}
	return rx, tx, found
}

type Mount struct{ Device, MountPoint, FSType string }

// Apenas sistemas de arquivos de armazenamento real.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true,
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ParseMounts lê /proc/mounts mantendo só volumes reais. Bind mounts e subvolumes do
// mesmo dispositivo são deduplicados, ficando o ponto de montagem de caminho mais curto.
func ParseMounts(s string, maxDisks int) []Mount {
	best := map[string]Mount{}
	var order []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		m := Mount{Device: f[0], MountPoint: unescapeMount(f[1]), FSType: f[2]}
		if !realFS[m.FSType] || (!strings.HasPrefix(m.Device, "/dev/") && m.FSType != "zfs") {
			continue
		}
		if strings.Contains(m.MountPoint, "/var/lib/docker/") || strings.Contains(m.MountPoint, "/var/lib/kubelet/") {
			continue
		}
		cur, seen := best[m.Device]
		if !seen {
			order = append(order, m.Device)
			best[m.Device] = m
		} else if len(m.MountPoint) < len(cur.MountPoint) {
			best[m.Device] = m
		}
	}
	out := make([]Mount, 0, len(order))
	for _, dev := range order {
		if len(out) >= maxDisks {
			break
		}
		out = append(out, best[dev])
	}
	return out
}

// ParseOSRelease extrai NAME e VERSION_ID de /etc/os-release.
func ParseOSRelease(s string) (name, version string) {
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "NAME":
			name = v
		case "VERSION_ID":
			version = v
		}
	}
	return name, version
}
