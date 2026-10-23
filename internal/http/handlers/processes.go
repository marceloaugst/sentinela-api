package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sentinela/internal/http/response"
	"sentinela/internal/procs"
	"sentinela/internal/servers"
	"sentinela/internal/svcactions"
	"sentinela/internal/validation"
)

// MaxProcessesBodyBytes cobre os 500 processos aceitos, com linha de comando.
const MaxProcessesBodyBytes = 512 << 10

// ProcHistoryStore é o que os handlers precisam do ClickHouse para o histórico dos maiores consumidores.
type ProcHistoryStore interface {
	Ready() bool
	InsertProcTop(ctx context.Context, serverID string, samples []procs.TopSample) error
	ProcTopRange(ctx context.Context, serverID string, from, to time.Time, limit int) ([]procs.TopSample, error)
}

const (
	maxHistoryRange = 7 * 24 * time.Hour
	maxHistoryRows  = 5000
)

// Processes expõe os processos do servidor (enviados pelo agente) e o pedido de encerrar.
type Processes struct {
	Repo    *procs.Repository
	Actions *svcactions.Repository
	Servers *servers.Repository
	Log     *slog.Logger
	History ProcHistoryStore // nil = sem ClickHouse

	TrustProxy bool
}

func (h Processes) server(w http.ResponseWriter, r *http.Request, id string) bool {
	if _, err := h.Servers.Get(r.Context(), id); err != nil {
		if errors.Is(err, servers.ErrNotFound) {
			response.NotFound(w)
			return false
		}
		h.Log.Error("falha ao buscar servidor", "err", err)
		response.Internal(w)
		return false
	}
	return true
}

// GET /servers/{id}/processes?sort=cpu|memory|pid|name&limit=&q=
// Devolve o último retrato do agente. A lista traz os processos que mais usam CPU e memória (até 300), não necessariamente
// todos: `total` é quantos existem no servidor. Cada processo traz `actions` ([] se não pode ser encerrado) e, nesse caso,
// `restriction` + `restriction_message` explicando o motivo.
func (h Processes) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()
	sortBy := q.Get("sort")
	switch sortBy {
	case "", "cpu", "memory", "pid", "name":
	default:
		response.Validation(w, validation.Problems{{Field: "sort", Message: "deve ser cpu, memory, pid ou name"}})
		return
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > procs.MaxProcesses {
			response.Validation(w, validation.Problems{{Field: "limit", Message: "deve ser um inteiro entre 1 e " + strconv.Itoa(procs.MaxProcesses)}})
			return
		}
		limit = n
	}
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if len(search) > 100 {
		response.Validation(w, validation.Problems{{Field: "q", Message: "máximo de 100 caracteres"}})
		return
	}
	if !h.server(w, r, id) {
		return
	}
	rep, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		h.Log.Error("falha ao ler processos do servidor", "err", err, "server_id", id)
		response.Internal(w)
		return
	}
	if rep == nil {
		response.JSON(w, http.StatusOK, map[string]any{
			"status": "unknown", "message": "O agente ainda não informou os processos deste servidor.",
			"checked_at": nil, "cpus": 0, "memory_total_bytes": 0, "total": 0, "matched": 0, "processes": []procs.Process{},
		}, nil)
		return
	}
	list := rep.Processes
	if search != "" {
		kept := list[:0:0]
		for _, p := range list {
			if strings.Contains(strings.ToLower(p.Name), search) || strings.Contains(strings.ToLower(p.Cmdline), search) ||
				strings.Contains(strings.ToLower(p.User), search) || strings.Contains(strconv.Itoa(p.PID), search) {
				kept = append(kept, p)
			}
		}
		list = kept
	}
	sortProcesses(list, sortBy)
	matched := len(list)
	if len(list) > limit {
		list = list[:limit]
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"status": "ok", "message": "", "checked_at": rep.CheckedAt, "cpus": rep.CPUs,
		"memory_total_bytes": rep.MemoryTotalBytes, "total": rep.Total, "matched": matched, "processes": list,
	}, nil)
}

func sortProcesses(l []procs.Process, by string) {
	less := func(i, j int) bool {
		a, b := l[i], l[j]
		switch by {
		case "memory":
			if a.MemoryBytes != b.MemoryBytes {
				return a.MemoryBytes > b.MemoryBytes
			}
		case "pid":
			return a.PID < b.PID
		case "name":
			if a.Name != b.Name {
				return strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
		default:
			if a.CPUPercent != b.CPUPercent {
				return a.CPUPercent > b.CPUPercent
			}
			if a.MemoryBytes != b.MemoryBytes {
				return a.MemoryBytes > b.MemoryBytes
			}
		}
		return a.PID < b.PID
	}
	sort.SliceStable(l, less)
}

type historySample struct {
	At        time.Time        `json:"at"`
	Processes []historyProcess `json:"processes"`
}

type historyProcess struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	User        string  `json:"user"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes int64   `json:"memory_bytes"`
}

// GET /servers/{id}/processes/history?from=&to=
// Quem mais usava CPU e memória no passado: a cada leitura do agente (~30 s; ~15 s quando CPU ou RAM passam de 85%),
// os 5 maiores por CPU e os 5 maiores por memória. Use para investigar um pico: passe a janela do alerta em from/to.
// Padrão: última hora; no máximo 7 dias. `samples` vem da leitura mais antiga para a mais nova.
func (h Processes) HistoryList(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	now := time.Now().UTC()
	to, from := now, now.Add(-time.Hour)
	var p validation.Problems
	q := r.URL.Query()
	parse := func(name string, dst *time.Time) {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				p.Add(name, "use o formato RFC 3339 (2026-10-23T03:12:00Z)")
				return
			}
			*dst = t.UTC()
		}
	}
	parse("to", &to)
	if q.Get("from") == "" && q.Get("to") != "" {
		from = to.Add(-time.Hour)
	}
	parse("from", &from)
	if len(p) == 0 && (!from.Before(to) || to.Sub(from) > maxHistoryRange) {
		p.Add("from", "deve ser anterior a to e a janela vai até 7 dias")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if h.History == nil || !h.History.Ready() {
		response.Error(w, http.StatusServiceUnavailable, "LOGS_UNAVAILABLE", "O armazenamento de logs não está disponível.")
		return
	}
	if !h.server(w, r, id) {
		return
	}
	rows, err := h.History.ProcTopRange(r.Context(), id, from, to, maxHistoryRows)
	if err != nil {
		h.Log.Error("falha ao ler o histórico de processos", "err", err, "server_id", id)
		response.Internal(w)
		return
	}
	out := []historySample{}
	for _, row := range rows {
		if n := len(out); n == 0 || !out[n-1].At.Equal(row.At) {
			out = append(out, historySample{At: row.At, Processes: []historyProcess{}})
		}
		last := &out[len(out)-1]
		last.Processes = append(last.Processes, historyProcess{PID: row.PID, Name: row.Name, User: row.User, CPUPercent: row.CPUPercent, MemoryBytes: row.MemoryBytes})
	}
	response.JSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "samples": out, "truncated": len(rows) >= maxHistoryRows}, nil)
}

type processActionInput struct {
	Action    string `json:"action"`
	StartTime uint64 `json:"start_time"`
}

// POST /servers/{id}/processes/{pid}/actions: pede ao agente para encerrar o processo (terminate = SIGTERM, kill = SIGKILL).
// `start_time` (do próprio item da lista) é obrigatório: garante que é o mesmo processo e não outro com o mesmo pid.
// Responde 202; acompanhe por GET /service-commands/{id} (o mesmo dos serviços).
func (h Processes) Request(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	pid, err := strconv.Atoi(chi.URLParam(r, "pid"))
	if err != nil || pid < 2 {
		response.NotFound(w)
		return
	}
	var in processActionInput
	if !response.Decode(w, r, &in) {
		return
	}
	var p validation.Problems
	if !procs.ValidAction(in.Action) {
		p.Add("action", "deve ser terminate ou kill")
	}
	if in.StartTime == 0 {
		p.Add("start_time", "é obrigatório (campo start_time do processo)")
	}
	if len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if !h.server(w, r, id) {
		return
	}
	cmd, err := h.Actions.RequestProcess(r.Context(), auditCtx(r, h.TrustProxy), id, pid, in.StartTime, in.Action)
	switch {
	case err == nil:
		response.JSON(w, http.StatusAccepted, cmd, nil)
	case errors.Is(err, svcactions.ErrNoDiscovery):
		response.NotFound(w)
	case errors.Is(err, svcactions.ErrNotActionable):
		response.Error(w, http.StatusUnprocessableEntity, "ACTION_NOT_ALLOWED",
			"Este processo não pode ser encerrado por aqui (veja restriction_message na lista).")
	case errors.Is(err, svcactions.ErrBusy):
		response.Error(w, http.StatusConflict, "COMMAND_IN_PROGRESS", "Já existe um pedido em andamento para este processo.")
	default:
		h.Log.Error("erro ao pedir encerramento de processo", "err", err, "server_id", id)
		response.Internal(w)
	}
}

// ---- agente ----

// POST /agent/processes: retrato dos processos do servidor da credencial.
func (h Agent) PostProcesses(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var rep procs.Report
	if !response.Decode(w, r, &rep) {
		return
	}
	if p := rep.Validate(h.now()); len(p) > 0 {
		response.Validation(w, p)
		return
	}
	if err := h.Procs.Replace(r.Context(), id.ServerID, rep); err != nil {
		h.Log.Error("falha ao gravar retrato dos processos", "err", err, "server_id", id.ServerID)
		response.Internal(w)
		return
	}
	// Histórico dos maiores consumidores: melhor esforço (sem ClickHouse, a tela atual continua funcionando).
	if h.ProcHistory != nil && h.ProcHistory.Ready() {
		hctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		if err := h.ProcHistory.InsertProcTop(hctx, id.ServerID, rep.TopSamples(procs.TopN)); err != nil {
			h.Log.Warn("falha ao gravar o histórico de processos", "err", err, "server_id", id.ServerID)
		}
		cancel()
	}
	response.JSON(w, http.StatusOK, map[string]any{"stored": len(rep.Processes)}, nil)
}
