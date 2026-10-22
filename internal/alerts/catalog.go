package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Prioridades dos incidentes. P1 e P2 viram severidade "critical" (notificam o canal padrão); P3 é
// "warning" (aparece no painel) e P4 é "info" (histórico).
const (
	P1 = 1 // crítico: notificação imediata
	P2 = 2 // alto: notificar rapidamente e investigar
	P3 = 3 // atenção: programar a correção antes de virar incidente
	P4 = 4 // informativo: só histórico
)

// SeverityOf traduz a prioridade para a severidade usada pelos canais de notificação.
func SeverityOf(priority int) string {
	switch priority {
	case P1, P2:
		return "critical"
	case P3:
		return "warning"
	}
	return "info"
}

// Spec é uma regra automática. O conjunto é fixo no código: não há cadastro nem edição pela API.
type Spec struct {
	Code        string
	Name        string
	Description string
	Metric      string
	Operator    string
	Threshold   float64
	Priority    int
	Duration    int // segundos com a condição verdadeira antes de alertar
	Recovery    int // segundos com a condição falsa antes de resolver
}

// Catalog reúne tudo o que o Sentinela vigia sozinho com os dados que o agente já envia. Todas as
// regras valem para todos os servidores ativos.
var Catalog = []Spec{
	{Code: "server_offline", Name: "Servidor sem comunicação", Metric: MetricOffline, Operator: ">", Threshold: 120,
		Priority: P1, Duration: 0, Recovery: 60,
		Description: "O servidor ficou mais de 2 minutos sem enviar dados ao monitoramento."},
	{Code: "service_down", Name: "Serviço indisponível", Metric: MetricServiceDown, Operator: "==", Threshold: 1,
		Priority: P1, Duration: 120, Recovery: 60,
		Description: "Um serviço descoberto automaticamente (Nginx, PostgreSQL, Redis, Docker...) parou por mais de 2 minutos."},
	{Code: "disk_critical", Name: "Disco quase cheio", Metric: MetricDisk, Operator: ">", Threshold: 95,
		Priority: P1, Duration: 60, Recovery: 120,
		Description: "Algum volume passou de 95% de ocupação."},
	{Code: "memory_low", Name: "Memória RAM quase esgotada", Metric: MetricMemory, Operator: ">", Threshold: 90,
		Priority: P2, Duration: 120, Recovery: 120,
		Description: "A RAM disponível está abaixo de 10% há mais de 2 minutos."},
	{Code: "cpu_high", Name: "CPU em uso excessivo", Metric: MetricCPU, Operator: ">", Threshold: 90,
		Priority: P2, Duration: 300, Recovery: 120,
		Description: "A CPU ficou acima de 90% por 5 minutos."},
	{Code: "load_high", Name: "Load average elevado", Metric: MetricLoadPerCPU, Operator: ">", Threshold: 2,
		Priority: P2, Duration: 300, Recovery: 120,
		Description: "O load average (1 min) ficou acima de 2 vezes a quantidade de CPUs por 5 minutos."},
	{Code: "disk_high", Name: "Disco com pouco espaço", Metric: MetricDisk, Operator: ">", Threshold: 80,
		Priority: P3, Duration: 300, Recovery: 300,
		Description: "Algum volume passou de 80% de ocupação."},
	{Code: "swap_high", Name: "Swap em uso elevado", Metric: MetricSwap, Operator: ">", Threshold: 50,
		Priority: P3, Duration: 600, Recovery: 300,
		Description: "Mais de 50% do swap está em uso há 10 minutos: sinal de falta de memória."},
	// ---- métricas de sistema (ClickHouse) ----
	{Code: "oom_kill", Name: "OOM Killer ativo", Metric: MetricOOM, Operator: ">", Threshold: 0,
		Priority: P2, Duration: 0, Recovery: 60,
		Description: "O kernel encerrou processos por falta de memória nos últimos 10 minutos."},
	{Code: "inodes_high", Name: "Inodes quase esgotados", Metric: MetricInodes, Operator: ">", Threshold: 90,
		Priority: P2, Duration: 120, Recovery: 300,
		Description: "Algum volume usou mais de 90% dos inodes: o disco pode recusar gravações mesmo com espaço livre."},
	{Code: "cert_critical", Name: "Certificado HTTPS vence em até 1 dia", Metric: MetricCert, Operator: "<", Threshold: 2,
		Priority: P2, Duration: 0, Recovery: 3600,
		Description: "Um certificado do Let's Encrypt vence em menos de 2 dias (ou já venceu)."},
	{Code: "disk_latency", Name: "Latência de disco elevada", Metric: MetricDiskLatency, Operator: ">", Threshold: 200,
		Priority: P3, Duration: 300, Recovery: 300,
		Description: "A latência média por operação de um disco passou de 200 ms por 5 minutos."},
	{Code: "cert_expiring", Name: "Certificado HTTPS próximo do vencimento", Metric: MetricCert, Operator: "<", Threshold: 7,
		Priority: P3, Duration: 0, Recovery: 3600,
		Description: "Um certificado do Let's Encrypt vence em menos de 7 dias."},
	{Code: "ntp_unsynchronized", Name: "Relógio sem sincronização (NTP)", Metric: MetricNTP, Operator: ">", Threshold: 0,
		Priority: P3, Duration: 600, Recovery: 300,
		Description: "O systemd-timesyncd informa que o relógio não está sincronizado há mais de 10 minutos."},
	{Code: "security_updates", Name: "Atualizações de segurança pendentes", Metric: MetricUpdates, Operator: ">", Threshold: 0,
		Priority: P3, Duration: 3600, Recovery: 300,
		Description: "Há atualizações de segurança do sistema operacional aguardando instalação."},
}

// SyncCatalog grava o catálogo no PostgreSQL (upsert pelo código) e arquiva toda regra que não
// pertence a ele, como as criadas à mão antes da automação. Os alertas e incidentes dessas regras
// são resolvidos pelo avaliador no próximo ciclo. É idempotente e roda a cada inicialização, então
// mudar um limite no código basta para aplicá-lo no banco.
func SyncCatalog(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	codes := make([]string, 0, len(Catalog))
	for _, s := range Catalog {
		codes = append(codes, s.Code)
		if _, err := tx.Exec(ctx, `INSERT INTO alert_rules (code, name, description, metric_name, operator, threshold, priority, severity,
				duration_seconds, recovery_seconds, server_id, is_enabled)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,true)
			ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, metric_name = EXCLUDED.metric_name,
				operator = EXCLUDED.operator, threshold = EXCLUDED.threshold, priority = EXCLUDED.priority, severity = EXCLUDED.severity,
				duration_seconds = EXCLUDED.duration_seconds, recovery_seconds = EXCLUDED.recovery_seconds, server_id = NULL,
				is_enabled = true, deleted_at = NULL,
				updated_at = CASE WHEN (alert_rules.name, alert_rules.description, alert_rules.metric_name, alert_rules.operator, alert_rules.threshold,
					alert_rules.priority, alert_rules.severity, alert_rules.duration_seconds, alert_rules.recovery_seconds, alert_rules.is_enabled,
					alert_rules.deleted_at IS NULL, alert_rules.server_id IS NULL)
					IS NOT DISTINCT FROM (EXCLUDED.name, EXCLUDED.description, EXCLUDED.metric_name, EXCLUDED.operator, EXCLUDED.threshold,
					EXCLUDED.priority, EXCLUDED.severity, EXCLUDED.duration_seconds, EXCLUDED.recovery_seconds, true, true, true)
					THEN alert_rules.updated_at ELSE now() END`,
			s.Code, s.Name, s.Description, s.Metric, s.Operator, s.Threshold, s.Priority, SeverityOf(s.Priority), s.Duration, s.Recovery); err != nil {
			return fmt.Errorf("regra %s: %w", s.Code, err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE alert_rules SET deleted_at = now(), is_enabled = false, updated_at = now()
		WHERE deleted_at IS NULL AND (code IS NULL OR code <> ALL($1))`, codes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
