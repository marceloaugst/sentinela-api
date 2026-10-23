package procs

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Tipos de consumo.
const (
	KindCPU    = "cpu"
	KindMemory = "memory"
)

// TopN é quantos processos de cada tipo (CPU e memória) vão para o histórico a cada relatório.
const TopN = 5

// TopSample é um processo no histórico dos maiores consumidores (ClickHouse). Sem linha de comando, de propósito:
// o histórico é longo e não precisa dela.
type TopSample struct {
	At          time.Time `json:"at"`
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	User        string    `json:"user"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemoryBytes int64     `json:"memory_bytes"`
}

// TopSamples escolhe os n que mais usam CPU e os n que mais usam memória (união, sem repetir).
func (r Report) TopSamples(n int) []TopSample {
	if len(r.Processes) == 0 {
		return nil
	}
	l := make([]Process, len(r.Processes))
	copy(l, r.Processes)
	chosen := map[int]bool{}
	var out []TopSample
	add := func(p Process) {
		if chosen[p.PID] {
			return
		}
		chosen[p.PID] = true
		out = append(out, TopSample{At: r.CheckedAt, PID: p.PID, Name: p.Name, User: p.User, CPUPercent: p.CPUPercent, MemoryBytes: p.MemoryBytes})
	}
	sort.SliceStable(l, func(i, j int) bool { return l[i].CPUPercent > l[j].CPUPercent })
	for i := 0; i < n && i < len(l); i++ {
		if l[i].CPUPercent > 0 {
			add(l[i])
		}
	}
	sort.SliceStable(l, func(i, j int) bool { return l[i].MemoryBytes > l[j].MemoryBytes })
	for i := 0; i < n && i < len(l); i++ {
		add(l[i])
	}
	return out
}

// Culprit é um consumidor (processos de mesmo nome somados, como os workers do nginx) na janela de um alerta.
type Culprit struct {
	Name            string  `json:"name"`
	User            string  `json:"user"`
	CPUPercent      float64 `json:"cpu_percent"`       // média na janela (100 = um núcleo)
	CPUPeak         float64 `json:"cpu_peak"`          // maior valor numa leitura
	MemoryBytes     int64   `json:"memory_bytes"`      // média na janela
	MemoryPeakBytes int64   `json:"memory_peak_bytes"` // maior valor numa leitura
}

// Culprits é o que fica gravado no alerta. Source: "history" (média das leituras da janela) ou "snapshot"
// (só a última leitura, quando não há histórico).
type Culprits struct {
	Kind          string    `json:"kind"`
	Source        string    `json:"source"`
	WindowSeconds int       `json:"window_seconds"`
	At            time.Time `json:"at"`
	Processes     []Culprit `json:"processes"`
}

// CulpritsFromSnapshot reduz a última leitura aos n maiores consumidores do tipo, somando processos de mesmo nome.
func CulpritsFromSnapshot(rep Report, kind string, n int) Culprits {
	by := map[string]*Culprit{}
	for _, p := range rep.Processes {
		c := by[p.Name]
		if c == nil {
			c = &Culprit{Name: p.Name, User: p.User}
			by[p.Name] = c
		}
		c.CPUPercent += p.CPUPercent
		c.CPUPeak += p.CPUPercent
		c.MemoryBytes += p.MemoryBytes
		c.MemoryPeakBytes += p.MemoryBytes
	}
	list := make([]Culprit, 0, len(by))
	for _, c := range by {
		list = append(list, *c)
	}
	SortCulprits(list, kind)
	if len(list) > n {
		list = list[:n]
	}
	return Culprits{Kind: kind, Source: "snapshot", At: rep.CheckedAt, Processes: list}
}

// SortCulprits ordena do maior para o menor consumo do tipo.
func SortCulprits(l []Culprit, kind string) {
	sort.SliceStable(l, func(i, j int) bool {
		if kind == KindMemory {
			return l[i].MemoryBytes > l[j].MemoryBytes
		}
		return l[i].CPUPercent > l[j].CPUPercent
	})
}

// Text é a frase acrescentada à mensagem do alerta (vazia se não há consumidores relevantes).
func (c Culprits) Text() string {
	var parts []string
	for _, p := range c.Processes {
		switch {
		case c.Kind == KindMemory && p.MemoryBytes > 0:
			parts = append(parts, fmt.Sprintf("%s %s", p.Name, humanBytes(p.MemoryBytes)))
		case c.Kind == KindCPU && p.CPUPercent >= 0.5:
			parts = append(parts, fmt.Sprintf("%s %.1f%% de CPU", p.Name, p.CPUPercent))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	what := "CPU"
	if c.Kind == KindMemory {
		what = "memória"
	}
	when := "na última leitura"
	if c.Source == "history" && c.WindowSeconds > 0 {
		when = fmt.Sprintf("média dos últimos %d min", int(math.Ceil(float64(c.WindowSeconds)/60)))
	}
	return fmt.Sprintf("Maiores consumidores de %s (%s): %s.", what, when, strings.Join(parts, ", "))
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d KB", b>>10)
}
