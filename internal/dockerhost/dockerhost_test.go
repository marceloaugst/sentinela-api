package dockerhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	idRunning = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idExited  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idCreated = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestAllowed(t *testing.T) {
	cases := map[string][]string{
		"running": {"restart"}, "restarting": {"restart"},
		"exited": {"start"}, "created": {"start"}, "dead": {"start"},
		"paused": {}, "removing": {},
	}
	for state, want := range cases {
		if got := Allowed(state); !reflect.DeepEqual(got, want) {
			t.Errorf("Allowed(%s) = %v; esperado %v", state, got, want)
		}
	}
}

func TestExplain(t *testing.T) {
	cases := []struct {
		state string
		code  int
		oom   bool
		err   string
		want  string
	}{
		{"exited", 1, false, "", "Saiu com erro, código 1."},
		{"exited", 0, false, "", "Encerrou normalmente (código 0)."},
		{"exited", 137, false, "", "Encerrado pelo sinal 9 (código 137)."},
		{"exited", 137, true, "", "Encerrado por falta de memória (OOM killer), código 137."},
		{"exited", 127, false, "exec: \"x\": executable file not found", "Erro do Docker: exec: \"x\": executable file not found"},
		{"created", 0, false, "", "Criado, mas nunca iniciado."},
	}
	for _, c := range cases {
		if got := Explain(c.state, c.code, c.oom, c.err); got != c.want {
			t.Errorf("Explain(%v) = %q; esperado %q", c, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	ok := Report{CheckedAt: now, Status: StatusOK, Containers: []Container{
		{ID: idRunning, Name: "web", State: "running", LogTail: "linha\x00 1\nlinha 2"},
	}}
	if p := ok.Validate(now); len(p) != 0 {
		t.Fatalf("relatório válido recusado: %v", p)
	}
	if strings.ContainsRune(ok.Containers[0].LogTail, 0) || !strings.Contains(ok.Containers[0].LogTail, "\n") {
		t.Errorf("limpeza do log: %q", ok.Containers[0].LogTail)
	}
	bad := map[string]Report{
		"status":        {CheckedAt: now, Status: "x"},
		"sem data":      {Status: StatusOK},
		"id curto":      {CheckedAt: now, Status: StatusOK, Containers: []Container{{ID: "abc", State: "running"}}},
		"id injeção":    {CheckedAt: now, Status: StatusOK, Containers: []Container{{ID: strings.Repeat("a", 63) + "/", State: "running"}}},
		"estado":        {CheckedAt: now, Status: StatusOK, Containers: []Container{{ID: idRunning, State: "x"}}},
		"duplicado":     {CheckedAt: now, Status: StatusOK, Containers: []Container{{ID: idRunning, State: "running"}, {ID: idRunning, State: "exited"}}},
		"sem docker":    {CheckedAt: now, Status: StatusNotInstalled, Containers: []Container{{ID: idRunning, State: "running"}}},
		"data distante": {CheckedAt: now.Add(48 * time.Hour), Status: StatusOK},
	}
	for name, r := range bad {
		if p := r.Validate(now); len(p) == 0 {
			t.Errorf("%s: deveria ser recusado", name)
		}
	}
	many := Report{CheckedAt: now, Status: StatusOK, Containers: make([]Container, MaxContainers+1)}
	if p := many.Validate(now); len(p) == 0 {
		t.Error("excesso de containers deveria ser recusado")
	}
}

func TestDemux(t *testing.T) {
	var b bytes.Buffer
	for _, f := range []struct {
		stream byte
		text   string
	}{{1, "saida\n"}, {2, "erro: falhou\n"}} {
		hdr := make([]byte, 8)
		hdr[0] = f.stream
		binary.BigEndian.PutUint32(hdr[4:], uint32(len(f.text)))
		b.Write(hdr)
		b.WriteString(f.text)
	}
	if got := demux(&b); got != "saida\nerro: falhou\n" {
		t.Errorf("demux = %q", got)
	}
	if got := demux(strings.NewReader("texto solto sem cabeçalho")); got != "" {
		t.Errorf("fluxo inválido deveria dar vazio: %q", got)
	}
}

// fakeDaemon sobe um "daemon Docker" falso num socket Unix.
type fakeDaemon struct {
	calls []string
	state map[string]string // id -> estado após start/restart
}

func (f *fakeDaemon) serve(t *testing.T) *Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("sem socket Unix:", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"Version": "27"})
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": idRunning, "Names": []string{"/web"}, "Image": "nginx", "State": "running", "Status": "Up 3 hours"},
			{"Id": idExited, "Names": []string{"/api"}, "Image": "app:1", "State": "exited", "Status": "Exited (1) 2 minutes ago"},
			{"Id": idCreated, "Names": []string{"/novo"}, "Image": "app:2", "State": "created", "Status": "Created"},
		})
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id, op := parts[1], parts[2]
		switch op {
		case "json":
			st := map[string]any{"Status": "exited", "Running": false, "ExitCode": 1, "Error": "", "OOMKilled": false,
				"StartedAt": "2026-10-23T10:00:00Z", "FinishedAt": "2026-10-23T10:05:00Z"}
			if id == idCreated {
				st["ExitCode"] = 0
				st["StartedAt"] = "0001-01-01T00:00:00Z"
			}
			if f.state[id] == "running" {
				st["Status"], st["Running"] = "running", true
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"State": st, "Config": map[string]any{"Tty": false}})
		case "logs":
			msg := "Error: cannot connect to database\n"
			hdr := make([]byte, 8)
			hdr[0] = 2
			binary.BigEndian.PutUint32(hdr[4:], uint32(len(msg)))
			_, _ = w.Write(append(hdr, msg...))
		case "start", "restart":
			if id == idCreated {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"driver failed programming external connectivity: port is already allocated"}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l) //nolint:errcheck
	t.Cleanup(func() { srv.Close() })
	return NewClient(sock)
}

func TestSnapshot(t *testing.T) {
	f := &fakeDaemon{}
	c := f.serve(t)
	rep := c.Snapshot(context.Background(), time.Now())
	if rep.Status != StatusOK || len(rep.Containers) != 3 {
		t.Fatalf("snapshot: %+v", rep)
	}
	web, api, novo := rep.Containers[0], rep.Containers[1], rep.Containers[2]
	if web.Name != "web" || web.Error != "" || web.LogTail != "" || web.ExitCode != nil {
		t.Errorf("ativo não deve ter erro nem log: %+v", web)
	}
	if api.Error != "Saiu com erro, código 1." || api.ExitCode == nil || *api.ExitCode != 1 ||
		!strings.Contains(api.LogTail, "cannot connect to database") || api.FinishedAt == nil {
		t.Errorf("inativo sem diagnóstico: %+v", api)
	}
	if novo.Error != "Criado, mas nunca iniciado." || novo.ExitCode != nil || novo.LogTail != "" || novo.StartedAt != nil {
		t.Errorf("container criado: %+v", novo)
	}
	if p := (&rep).Validate(time.Now()); len(p) != 0 {
		t.Errorf("o relatório do próprio agente deve ser válido: %v", p)
	}
}

func TestDetect(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "nao-existe.sock"))
	if st, msg := c.Detect(context.Background()); st != StatusNotInstalled || msg == "" {
		t.Errorf("sem socket: %s %q", st, msg)
	}
	// socket sem ninguém atendendo (o Close do Go remove o arquivo): nunca pode dar ok
	sock := filepath.Join(t.TempDir(), "morto.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	l.Close()
	if st, _ := NewClient(sock).Detect(context.Background()); st == StatusOK {
		t.Errorf("daemon parado não pode ser ok")
	}
}

func TestStartRestartErrors(t *testing.T) {
	f := &fakeDaemon{state: map[string]string{idExited: "running"}}
	c := f.serve(t)
	ctx := context.Background()
	if err := c.Restart(ctx, idRunning); err != nil {
		t.Errorf("restart: %v", err)
	}
	err := c.Start(ctx, idCreated)
	if err == nil || !strings.Contains(err.Error(), "port is already allocated") {
		t.Errorf("a mensagem do Docker deve chegar ao usuário: %v", err)
	}
	if running, _, err := c.Settled(ctx, idExited); err != nil || !running {
		t.Errorf("Settled ativo: %v %v", running, err)
	}
	if running, why, _ := c.Settled(ctx, idCreated); running || why == "" {
		t.Errorf("Settled inativo: %v %q", running, why)
	}
}
