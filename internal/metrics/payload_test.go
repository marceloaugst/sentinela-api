package metrics

import (
	"strings"
	"testing"
	"time"
)

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

func validPayload(now time.Time) Payload {
	cnt := 4
	return Payload{
		AgentVersion: "0.1.0",
		CollectedAt:  now.Add(-time.Second),
		Host:         Host{Hostname: "web-1", OS: "Ubuntu", OSVersion: "24.04", Architecture: "amd64", UptimeSeconds: i64(1000)},
		CPU:          CPU{UsagePercent: f64(12.5), Count: &cnt, LoadAverage: &LoadAverage{0.1, 0.2, 0.3}},
		Memory:       Memory{TotalBytes: 1000, UsedBytes: 400, AvailableBytes: 600, SwapTotalBytes: 100, SwapUsedBytes: 10},
		Network:      &Network{RXBytesTotal: 10, TXBytesTotal: 20},
		Disks:        []Disk{{MountPoint: "/", Filesystem: "ext4", TotalBytes: 100, UsedBytes: 40, AvailableBytes: 60}},
	}
}

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func problemFields(pl Payload) string {
	var sb strings.Builder
	for _, p := range pl.Validate(now) {
		sb.WriteString(p.Field + ";")
	}
	return sb.String()
}

func TestPayloadValid(t *testing.T) {
	pl := validPayload(now)
	if p := pl.Validate(now); len(p) != 0 {
		t.Fatalf("payload válido rejeitado: %v", p)
	}
}

func TestPayloadRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Payload)
		field  string
	}{
		{"sem versão", func(p *Payload) { p.AgentVersion = "" }, "agent_version"},
		{"sem collected_at", func(p *Payload) { p.CollectedAt = time.Time{} }, "collected_at"},
		{"futuro", func(p *Payload) { p.CollectedAt = now.Add(MaxFutureSkew + time.Minute) }, "collected_at"},
		{"antigo", func(p *Payload) { p.CollectedAt = now.Add(-MaxAge - time.Minute) }, "collected_at"},
		{"cpu ausente", func(p *Payload) { p.CPU.UsagePercent = nil }, "cpu.usage_percent"},
		{"cpu > 100", func(p *Payload) { p.CPU.UsagePercent = f64(100.1) }, "cpu.usage_percent"},
		{"cpu negativa", func(p *Payload) { p.CPU.UsagePercent = f64(-1) }, "cpu.usage_percent"},
		{"cpu NaN", func(p *Payload) { n := 0.0; n = n / n; p.CPU.UsagePercent = &n }, "cpu.usage_percent"},
		{"load negativo", func(p *Payload) { p.CPU.LoadAverage.M5 = -1 }, "cpu.load_average.m5"},
		{"cpus 0", func(p *Payload) { z := 0; p.CPU.Count = &z }, "cpu.count"},
		{"mem total 0", func(p *Payload) { p.Memory = Memory{} }, "memory.total_bytes"},
		{"mem usada > total", func(p *Payload) { p.Memory.UsedBytes = 2000 }, "memory.used_bytes"},
		{"mem disponível > total", func(p *Payload) { p.Memory.AvailableBytes = 2000 }, "memory.available_bytes"},
		{"mem negativa", func(p *Payload) { p.Memory.UsedBytes = -1 }, "memory.used_bytes"},
		{"swap usada > total", func(p *Payload) { p.Memory.SwapUsedBytes = 101 }, "memory.swap_used_bytes"},
		{"rede negativa", func(p *Payload) { p.Network.RXBytesTotal = -5 }, "network.rx_bytes_total"},
		{"disco relativo", func(p *Payload) { p.Disks[0].MountPoint = "var/log" }, "disks[0].mount_point"},
		{"disco usado > total", func(p *Payload) { p.Disks[0].UsedBytes = 101 }, "disks[0].used_bytes"},
		{"disco duplicado", func(p *Payload) { p.Disks = append(p.Disks, p.Disks[0]) }, "disks[1].mount_point"},
		{"discos demais", func(p *Payload) { p.Disks = make([]Disk, MaxDisks+1) }, "disks"},
		{"uptime negativo", func(p *Payload) { p.Host.UptimeSeconds = i64(-1) }, "host.uptime_seconds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pl := validPayload(now)
			c.mutate(&pl)
			if got := problemFields(pl); !strings.Contains(got, c.field+";") {
				t.Errorf("esperava problema em %q, obteve %q", c.field, got)
			}
		})
	}
}

func TestPayloadOptionalSectionsAllowed(t *testing.T) {
	pl := validPayload(now)
	pl.Network = nil
	pl.Disks = nil
	pl.CPU.LoadAverage = nil
	pl.CPU.Count = nil
	pl.Host.UptimeSeconds = nil
	if p := pl.Validate(now); len(p) != 0 {
		t.Errorf("seções opcionais ausentes deveriam ser aceitas: %v", p)
	}
}

func TestPayloadNormalizesTimestamp(t *testing.T) {
	pl := validPayload(now)
	loc := time.FixedZone("x", -3*3600)
	pl.CollectedAt = now.Add(-time.Second).In(loc).Add(123456 * time.Nanosecond)
	pl.Validate(now)
	if pl.CollectedAt.Location() != time.UTC || pl.CollectedAt.Nanosecond()%int(time.Millisecond) != 0 {
		t.Errorf("collected_at deveria ser UTC com precisão de ms: %v", pl.CollectedAt)
	}
}

func TestHeartbeatValidate(t *testing.T) {
	h := Heartbeat{AgentVersion: "1", Host: Host{Hostname: "x"}}
	if p := h.Validate(); len(p) != 0 {
		t.Errorf("%v", p)
	}
	bad := Heartbeat{}
	if p := bad.Validate(); len(p) != 1 {
		t.Errorf("sem versão deveria falhar: %v", p)
	}
}
