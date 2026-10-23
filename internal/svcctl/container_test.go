package svcctl

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sentinela/internal/dockerhost"
	"sentinela/internal/svcactions"
)

const (
	idUp    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idDown  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idCrash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// daemon falso: web (ativo), api (parado) e crash (inicia, mas morre na hora).
func fakeDocker(t *testing.T) (*dockerhost.Client, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	started := map[string]bool{idUp: true}
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"Version":"27"}`)) })
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": idUp, "Names": []string{"/web"}, "Image": "nginx", "State": "running"},
			{"Id": idDown, "Names": []string{"/api"}, "Image": "app", "State": "exited"},
			{"Id": idCrash, "Names": []string{"/crash"}, "Image": "app", "State": "exited"},
		})
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id, op := parts[1], parts[2]
		calls = append(calls, r.Method+" "+op+" "+id[:1])
		switch op {
		case "start", "restart":
			started[id] = id != idCrash
			w.WriteHeader(http.StatusNoContent)
		case "json":
			run := started[id]
			_ = json.NewEncoder(w).Encode(map[string]any{"State": map[string]any{"Running": run, "Status": "exited", "ExitCode": 3},
				"Config": map[string]any{}})
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l) //nolint:errcheck
	t.Cleanup(func() { srv.Close() })
	return dockerhost.NewClient(sock), &calls
}

func TestExecuteContainer(t *testing.T) {
	d, calls := fakeDocker(t)
	e := &Executor{Docker: d}
	ctx := context.Background()

	if st, msg := e.ExecuteContainer(ctx, idUp, "restart"); st != svcactions.StatusSucceeded || msg != "docker restart web" {
		t.Errorf("reiniciar ativo: %s %q", st, msg)
	}
	if st, msg := e.ExecuteContainer(ctx, idDown, "start"); st != svcactions.StatusSucceeded {
		t.Errorf("iniciar parado: %s %q", st, msg)
	}
	// subiu e caiu logo em seguida: a falha mostra o motivo
	if st, msg := e.ExecuteContainer(ctx, idCrash, "start"); st != svcactions.StatusFailed || !strings.Contains(msg, "código 3") {
		t.Errorf("container que morre ao iniciar: %s %q", st, msg)
	}

	*calls = nil
	// estado incompatível, id inexistente e entradas inválidas: nunca chegam a start/restart
	for _, c := range [][2]string{{idUp, "start"}, {idDown, "restart"}, {strings.Repeat("d", 64), "restart"},
		{"web", "restart"}, {idUp + "/../x", "restart"}, {idUp, "stop"}, {idUp, "remove"}} {
		if st, _ := e.ExecuteContainer(ctx, c[0], c[1]); st != svcactions.StatusFailed {
			t.Errorf("%v deveria falhar", c)
		}
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "POST") {
			t.Errorf("chamada indevida ao daemon: %s", c)
		}
	}
}
