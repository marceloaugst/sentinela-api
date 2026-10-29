package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/logstore"
	"sentinela/internal/procs"
	"sentinela/internal/sysmetrics"
	"sentinela/internal/telemetry"
)

// lockID: com várias instâncias da API, só uma avalia por vez.
const lockID int64 = 0x53454e45 // "SENE"

type Evaluator struct {
	Pool             *pgxpool.Pool
	Log              *slog.Logger
	HeartbeatTimeout time.Duration
	Metrics          *telemetry.Metrics // opcional
	System           SystemSource       // opcional: métricas de sistema no ClickHouse
	Procs            ProcSource         // opcional: histórico dos maiores consumidores (ClickHouse)
	Now              func() time.Time
}

func (e *Evaluator) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Evaluator) count(action string) {
	if e.Metrics != nil {
		e.Metrics.AlertTransitions.WithLabelValues(action).Inc()
	}
}

type serverSnap struct {
	ID, Name   string
	LastSeen   *time.Time
	CPU        *float64
	Mem        *float64
	Load       *float64
	LoadPerCPU *float64
	SwapPct    *float64
	DiskPct    *float64
	DiskMount  string
}

type serviceSnap struct {
	ID, Name, Type, Status string
	ServerID, ServerName   string
	LastError              string
}

// SystemSource fornece as métricas de sistema (ClickHouse). Ready=false ou erro = sem dados: nenhum alerta
// dessas métricas abre nem resolve até o dado voltar.
type SystemSource interface {
	Ready() bool
	LatestSystem(ctx context.Context, window time.Duration) ([]logstore.SystemValue, error)
}

// ProcSource fornece o histórico dos maiores consumidores (ClickHouse) para apontar o culpado de um alerta de
// CPU/memória. Sem ele (ou sem dados), o alerta usa a última leitura de processos guardada no PostgreSQL.
type ProcSource interface {
	Ready() bool
	ProcCulprits(ctx context.Context, serverID string, from, to time.Time, kind string, n int) ([]procs.Culprit, int, error)
}

const systemWindow = 10 * time.Minute

// sysReading é o valor de uma métrica de sistema já reduzido ao pior caso do servidor.
type sysReading struct {
	value   float64
	subject string
}

type snapshot struct {
	servers  []serverSnap
	services []serviceSnap
	system   map[string]map[string]sysReading // servidor -> métrica da regra -> leitura
}

// systemMetricMap traduz o nome gravado no ClickHouse para a métrica da regra e diz se vale o pior caso
// (máximo, ou mínimo para os dias de certificado) ou a soma da janela.
var systemMetricMap = map[string]struct {
	rule string
	mode string // "max" | "min" | "sum" | "last"
}{
	sysmetrics.OOMKills:        {MetricOOM, "sum"},
	sysmetrics.InodeUsed:       {MetricInodes, "max"},
	sysmetrics.DiskLatency:     {MetricDiskLatency, "max"},
	sysmetrics.NTPUnsynced:     {MetricNTP, "last"},
	sysmetrics.SecurityUpdates: {MetricUpdates, "last"},
	sysmetrics.CertDaysLeft:    {MetricCert, "min"},
}

func reduceSystem(vals []logstore.SystemValue) map[string]map[string]sysReading {
	out := map[string]map[string]sysReading{}
	for _, v := range vals {
		m, ok := systemMetricMap[v.Metric]
		if !ok {
			continue
		}
		x := v.Latest
		if m.mode == "sum" {
			x = v.Sum
		}
		if out[v.ServerID] == nil {
			out[v.ServerID] = map[string]sysReading{}
		}
		cur, has := out[v.ServerID][m.rule]
		if !has || (m.mode == "max" && x > cur.value) || (m.mode == "min" && x < cur.value) || m.mode == "sum" && x > cur.value ||
			(m.mode == "last" && x > cur.value) {
			out[v.ServerID][m.rule] = sysReading{x, v.Subject}
		}
	}
	return out
}

// loadSnapshot lê, em poucas consultas compartilhadas por todas as regras, o estado atual dos
// servidores ATIVOS (última amostra e pior disco) e de seus serviços.
func (e *Evaluator) loadSnapshot(ctx context.Context) (snapshot, error) {
	var snap snapshot
	rows, err := e.Pool.Query(ctx, `
		SELECT s.id, s.name, s.last_seen_at, m.cpu, m.mem_pct, m.load1, m.load_per_cpu, m.swap_pct, d.pct, COALESCE(d.mount, '')
		FROM servers s
		LEFT JOIN LATERAL (
			SELECT cpu_usage_percent AS cpu,
			       CASE WHEN memory_total_bytes > 0 THEN memory_used_bytes::float8 / memory_total_bytes * 100 END AS mem_pct,
			       load_average_1m AS load1,
			       CASE WHEN cpu_count > 0 THEN load_average_1m / cpu_count END AS load_per_cpu,
			       CASE WHEN swap_total_bytes > 0 THEN swap_used_bytes::float8 / swap_total_bytes * 100 END AS swap_pct
			FROM server_metrics WHERE server_id = s.id ORDER BY collected_at DESC LIMIT 1) m ON true
		LEFT JOIN LATERAL (
			SELECT used_bytes::float8 / total_bytes * 100 AS pct, mount_point AS mount
			FROM server_disks WHERE server_id = s.id AND total_bytes > 0
			ORDER BY used_bytes::float8 / total_bytes DESC, mount_point LIMIT 1) d ON true
		WHERE s.deleted_at IS NULL AND s.status = 'active'`)
	if err != nil {
		return snap, err
	}
	for rows.Next() {
		var s serverSnap
		if err := rows.Scan(&s.ID, &s.Name, &s.LastSeen, &s.CPU, &s.Mem, &s.Load, &s.LoadPerCPU, &s.SwapPct, &s.DiskPct, &s.DiskMount); err != nil {
			rows.Close()
			return snap, err
		}
		snap.servers = append(snap.servers, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snap, err
	}

	if e.System != nil && e.System.Ready() {
		vals, err := e.System.LatestSystem(ctx, systemWindow)
		if err != nil {
			e.Log.Warn("métricas de sistema indisponíveis; regras do ClickHouse mantêm o estado", "err", err)
		} else {
			snap.system = reduceSystem(vals)
			if snap.system == nil {
				snap.system = map[string]map[string]sysReading{}
			}
		}
	}

	rows, err = e.Pool.Query(ctx, `SELECT ms.id, ms.name, ms.service_type, ms.status, COALESCE(ms.last_error, ''), s.id, s.name
		FROM monitored_services ms JOIN servers s ON s.id = ms.server_id AND s.deleted_at IS NULL AND s.status = 'active'
		WHERE ms.deleted_at IS NULL`)
	if err != nil {
		return snap, err
	}
	defer rows.Close()
	for rows.Next() {
		var v serviceSnap
		if err := rows.Scan(&v.ID, &v.Name, &v.Type, &v.Status, &v.LastError, &v.ServerID, &v.ServerName); err != nil {
			return snap, err
		}
		snap.services = append(snap.services, v)
	}
	return snap, rows.Err()
}

func (e *Evaluator) online(s serverSnap, now time.Time) bool {
	return s.LastSeen != nil && now.Sub(*s.LastSeen) <= e.HeartbeatTimeout
}

func inScope(rule Rule, serverID string) bool {
	return rule.ServerID == nil || *rule.ServerID == serverID
}

// targets calcula os alvos e valores de uma regra a partir do snapshot.
//   - Métricas de recurso só valem com o servidor online (amostra atual); offline => sem dados.
//   - server_offline só avalia servidores que já se comunicaram alguma vez.
//   - service_down: serviços verificados pelo agente só valem com o servidor online (o agente é a
//     única fonte); estado "unknown" não é avaliado.
func (e *Evaluator) targets(rule Rule, snap snapshot, now time.Time) []Target {
	var out []Target
	if rule.MetricName == MetricServiceDown {
		online := map[string]bool{}
		for _, s := range snap.servers {
			online[s.ID] = e.online(s, now)
		}
		for _, v := range snap.services {
			if !inScope(rule, v.ServerID) {
				continue
			}
			id := v.ID
			t := Target{ServerID: v.ServerID, ServerName: v.ServerName, ServiceID: &id, ServiceName: v.Name}
			fresh := v.Type == "http" || online[v.ServerID]
			if fresh && v.Status != "unknown" {
				t.HasValue = true
				if v.Status == "down" {
					t.Value = 1
				}
				t.Detail = fmt.Sprintf("%q", v.Name)
				if v.LastError != "" && v.Status == "down" {
					t.Detail += ": " + v.LastError
				}
			}
			out = append(out, t)
		}
		return out
	}
	for _, s := range snap.servers {
		if !inScope(rule, s.ID) {
			continue
		}
		t := Target{ServerID: s.ID, ServerName: s.Name}
		online := e.online(s, now)
		switch rule.MetricName {
		case MetricOffline:
			if s.LastSeen != nil {
				t.HasValue, t.Value = true, now.Sub(*s.LastSeen).Seconds()
			}
		case MetricCPU:
			if online && s.CPU != nil {
				t.HasValue, t.Value = true, *s.CPU
			}
		case MetricMemory:
			if online && s.Mem != nil {
				t.HasValue, t.Value = true, *s.Mem
			}
		case MetricLoad:
			if online && s.Load != nil {
				t.HasValue, t.Value = true, *s.Load
			}
		case MetricLoadPerCPU:
			if online && s.LoadPerCPU != nil {
				t.HasValue, t.Value = true, *s.LoadPerCPU
			}
		case MetricSwap:
			if online && s.SwapPct != nil {
				t.HasValue, t.Value = true, *s.SwapPct
			}
		case MetricOOM, MetricInodes, MetricDiskLatency, MetricNTP, MetricUpdates, MetricCert:
			// snap.system nil = ClickHouse indisponível: sem dados (não abre nem resolve)
			if r, ok := snap.system[s.ID][rule.MetricName]; online && snap.system != nil {
				if ok {
					t.HasValue, t.Value, t.Detail = true, r.value, r.subject
				}
			}
		case MetricDisk:
			if online && s.DiskPct != nil {
				t.HasValue, t.Value, t.Detail = true, *s.DiskPct, s.DiskMount
			}
		}
		out = append(out, t)
	}
	return out
}

const activeAlertsSQL = `SELECT id, rule_id, server_id, service_id, incident_id, status, severity, message, pending_since, recovering_since, silenced
	FROM alerts WHERE status IN ('pending','firing','acknowledged')`

func scanAlertRow(row pgx.Row) (alertRow, error) {
	var a alertRow
	err := row.Scan(&a.ID, &a.RuleID, &a.ServerID, &a.ServiceID, &a.IncidentID, &a.Status, &a.Severity, &a.Message,
		&a.PendingSince, &a.RecoveringSince, &a.Silenced)
	return a, err
}

func loadActive(ctx context.Context, tx pgx.Tx, where string, args ...any) ([]alertRow, error) {
	rows, err := tx.Query(ctx, activeAlertsSQL+where+" ORDER BY triggered_at, id FOR UPDATE", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alertRow
	for rows.Next() {
		a, err := scanAlertRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Tick executa uma rodada completa de avaliação. Todo o estado está no banco, então qualquer
// instância (ou a mesma após reiniciar) continua exatamente de onde a anterior parou.
func (e *Evaluator) Tick(ctx context.Context) error {
	conn, err := e.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&got); err != nil {
		return err
	}
	if !got {
		return nil // outra instância está avaliando
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(uctx, "SELECT pg_advisory_unlock($1)", lockID)
	}()

	now := e.now()
	snap, err := e.loadSnapshot(ctx)
	if err != nil {
		return err
	}
	rules, err := e.enabledRules(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, rule := range rules {
		if err := e.evalRule(ctx, rule, e.targets(rule, snap, now), now); err != nil {
			e.Log.Error("falha ao avaliar regra", "rule_id", rule.ID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := e.resolveOrphans(ctx, now); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (e *Evaluator) enabledRules(ctx context.Context) ([]Rule, error) {
	rows, err := e.Pool.Query(ctx, `SELECT `+ruleCols+` FROM alert_rules WHERE is_enabled AND deleted_at IS NULL ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (e *Evaluator) evalRule(ctx context.Context, rule Rule, targets []Target, now time.Time) error {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	existing, err := loadActive(ctx, tx, " AND rule_id = $1", rule.ID)
	if err != nil {
		return err
	}
	byKey := make(map[string]alertRow, len(existing))
	for _, a := range existing {
		byKey[a.key()] = a
	}
	seen := make(map[string]bool, len(targets))

	for _, t := range targets {
		k := t.key()
		seen[k] = true
		cur, has := byKey[k]
		if !t.HasValue {
			continue // sem dados confiáveis: mantém o estado como está
		}
		st := State{}
		if has {
			st = cur.state()
		}
		cond := Compare(rule.Operator, t.Value, rule.Threshold)
		act := Decide(st, cond, now, rule.DurationSeconds, rule.RecoverySeconds)
		if err := e.apply(ctx, tx, rule, t, cur, has, act, now); err != nil {
			return fmt.Errorf("alerta %s: %w", k, err)
		}
	}
	// alertas cujo alvo saiu do escopo (servidor/serviço removido, desativado ou em manutenção)
	for _, a := range existing {
		if seen[a.key()] {
			continue
		}
		if a.Status == StatusPending {
			if _, err := tx.Exec(ctx, `DELETE FROM alerts WHERE id = $1`, a.ID); err != nil {
				return err
			}
			e.count("drop_pending")
			continue
		}
		if err := resolve(ctx, tx, a, ReasonOutOfScope, "sistema", now); err != nil {
			return err
		}
		e.count("resolve")
	}
	return tx.Commit(ctx)
}

func (e *Evaluator) apply(ctx context.Context, tx pgx.Tx, rule Rule, t Target, cur alertRow, has bool, act Action, now time.Time) error {
	var existing *alertRow
	if has {
		existing = &cur
	}
	switch act {
	case ActNone:
		if has { // atualiza o valor observado e o instante da última avaliação
			if _, err := tx.Exec(ctx, `UPDATE alerts SET value = $2, last_evaluated_at = $3 WHERE id = $1`, cur.ID, t.Value, now); err != nil {
				return err
			}
			if cur.Silenced {
				return releaseSilenced(ctx, tx, rule, t, cur, now)
			}
		}
	case ActStartPending:
		_, err := tx.Exec(ctx, `INSERT INTO alerts (rule_id, server_id, service_id, status, severity, message, value, pending_since, triggered_at, last_evaluated_at)
			VALUES ($1,$2,$3,'pending',$4,$5,$6,$7,$7,$7)`,
			rule.ID, t.ServerID, t.ServiceID, rule.Severity, Message(rule, t.Value, t.Detail), t.Value, now)
		e.count("start_pending")
		return err
	case ActDropPending:
		_, err := tx.Exec(ctx, `DELETE FROM alerts WHERE id = $1`, cur.ID)
		e.count("drop_pending")
		return err
	case ActFire:
		e.count("fire")
		t.Culprits = e.culprits(ctx, rule, t, now)
		return fire(ctx, tx, rule, t, existing, now)
	case ActClearRecovering:
		_, err := tx.Exec(ctx, `UPDATE alerts SET recovering_since = NULL, value = $2, last_evaluated_at = $3 WHERE id = $1`, cur.ID, t.Value, now)
		e.count("clear_recovering")
		return err
	case ActStartRecovering:
		_, err := tx.Exec(ctx, `UPDATE alerts SET recovering_since = $2, value = $3, last_evaluated_at = $2 WHERE id = $1`, cur.ID, now, t.Value)
		e.count("start_recovering")
		return err
	case ActResolve:
		e.count("resolve")
		return resolve(ctx, tx, cur, ReasonRecovered, "sistema", now)
	}
	return nil
}

// resolveOrphans fecha alertas de regras desativadas ou removidas.
func (e *Evaluator) resolveOrphans(ctx context.Context, now time.Time) error {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	alertsOf, err := loadActive(ctx, tx, ` AND rule_id IN (SELECT id FROM alert_rules WHERE NOT is_enabled OR deleted_at IS NOT NULL)`)
	if err != nil {
		return err
	}
	for _, a := range alertsOf {
		if a.Status == StatusPending {
			if _, err := tx.Exec(ctx, `DELETE FROM alerts WHERE id = $1`, a.ID); err != nil {
				return err
			}
			continue
		}
		reason := ReasonRuleDisabled
		var deleted bool
		if err := tx.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM alert_rules WHERE id = $1`, a.RuleID).Scan(&deleted); err != nil {
			return err
		}
		if deleted {
			reason = ReasonRuleDeleted
		}
		if err := resolve(ctx, tx, a, reason, "sistema", now); err != nil {
			return err
		}
		e.count("resolve")
	}
	return tx.Commit(ctx)
}

// culpritKind diz qual consumo explica o alerta (vazio = a regra não tem relação com processos).
func culpritKind(metric string) string {
	switch metric {
	case MetricCPU, MetricLoad, MetricLoadPerCPU:
		return procs.KindCPU
	case MetricMemory, MetricSwap, MetricOOM:
		return procs.KindMemory
	}
	return ""
}

const (
	culpritCount     = 3
	minCulpritWindow = 2 * time.Minute
	maxCulpritWindow = 15 * time.Minute
	snapshotMaxAge   = 2 * time.Minute
)

// culprits aponta os maiores consumidores de CPU/memória do servidor. Primeiro o histórico da janela em que a condição
// vinha valendo (média por nome de processo); sem histórico, a última leitura de processos, se for recente. Nunca falha o
// alerta: sem dados, o alerta sai sem a lista.
func (e *Evaluator) culprits(ctx context.Context, rule Rule, t Target, now time.Time) *procs.Culprits {
	kind := culpritKind(rule.MetricName)
	if kind == "" || t.ServiceID != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	window := time.Duration(rule.DurationSeconds) * time.Second
	window = min(max(window, minCulpritWindow), maxCulpritWindow)
	if e.Procs != nil && e.Procs.Ready() {
		list, samples, err := e.Procs.ProcCulprits(cctx, t.ServerID, now.Add(-window), now, kind, culpritCount)
		switch {
		case err != nil:
			e.Log.Debug("histórico de processos indisponível para o alerta", "err", err, "server_id", t.ServerID)
		case samples > 0 && len(list) > 0:
			return &procs.Culprits{Kind: kind, Source: "history", WindowSeconds: int(window.Seconds()), At: now, Processes: list}
		}
	}
	rep, err := procs.NewRepository(e.Pool).Get(cctx, t.ServerID)
	if err != nil || rep == nil || now.Sub(rep.CheckedAt) > snapshotMaxAge {
		return nil
	}
	c := procs.CulpritsFromSnapshot(*rep, kind, culpritCount)
	return &c
}
