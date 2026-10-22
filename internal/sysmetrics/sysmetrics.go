// Package sysmetrics define o contrato das métricas de sistema coletadas pelo agente além das de
// CPU/RAM/disco (OOM Killer, inodes, latência de disco, NTP, atualizações, certificados). Elas
// vão para o ClickHouse (tabela system_metrics) e alimentam as regras do catálogo de alertas.
package sysmetrics

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"sentinela/internal/logs"
	"sentinela/internal/validation"
)

// Nomes de métricas aceitos (vocabulário fechado).
const (
	OOMKills        = "oom_kills"          // processos mortos pelo OOM Killer desde a amostra anterior
	InodeUsed       = "inode_used_percent" // subject = ponto de montagem
	DiskLatency     = "disk_latency_ms"    // latência média por operação desde a amostra anterior; subject = dispositivo
	NTPUnsynced     = "ntp_unsynchronized" // 1 = relógio não sincronizado, 0 = sincronizado
	SecurityUpdates = "security_updates"   // atualizações de segurança pendentes
	CertDaysLeft    = "cert_days_left"     // dias até vencer; subject = domínio do certificado
)

var Metrics = map[string]bool{OOMKills: true, InodeUsed: true, DiskLatency: true, NTPUnsynced: true, SecurityUpdates: true, CertDaysLeft: true}

const (
	MaxSamples    = 500
	maxSubjectLen = 128
	maxFutureSkew = 2 * time.Minute
	maxAge        = time.Hour
)

type Sample struct {
	Time    time.Time `json:"time"`
	Metric  string    `json:"metric"`
	Subject string    `json:"subject"`
	Value   float64   `json:"value"`
}

// Batch é o corpo de POST /agent/system-metrics. BatchID torna o reenvio idempotente.
type Batch struct {
	BatchID string   `json:"batch_id"`
	Samples []Sample `json:"samples"`
}

var batchIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

func (b *Batch) Validate(now time.Time) validation.Problems {
	var p validation.Problems
	if !batchIDRe.MatchString(b.BatchID) {
		p.Add("batch_id", "deve ter de 8 a 64 caracteres [A-Za-z0-9-]")
	}
	if len(b.Samples) == 0 {
		p.Add("samples", "é obrigatório")
	}
	if len(b.Samples) > MaxSamples {
		p.Add("samples", fmt.Sprintf("no máximo %d amostras por lote", MaxSamples))
		return p
	}
	for i := range b.Samples {
		s := &b.Samples[i]
		f := func(n string) string { return fmt.Sprintf("samples[%d].%s", i, n) }
		if !Metrics[s.Metric] {
			p.Add(f("metric"), "métrica desconhecida")
		}
		s.Subject = strings.TrimSpace(logs.Clean(s.Subject, maxSubjectLen))
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value < -1e9 || s.Value > 1e12 {
			p.Add(f("value"), "valor fora do intervalo")
		}
		switch {
		case s.Time.IsZero():
			p.Add(f("time"), "é obrigatório")
		case s.Time.After(now.Add(maxFutureSkew)):
			p.Add(f("time"), "está no futuro além do tolerado")
		case s.Time.Before(now.Add(-maxAge)):
			p.Add(f("time"), "é antigo demais")
		}
		if len(p) >= 20 {
			break
		}
	}
	return p
}
