package logtail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinela/internal/agentclient"
	"sentinela/internal/logs"
)

// linesParser cria uma entrada por linha (type=ban, jail=<linha>).
type linesParser struct{}

func (linesParser) Idle(time.Time) []logs.Entry { return nil }
func (linesParser) Parse(line string) []logs.Entry {
	if line == "" || line[0] == '#' {
		return nil
	}
	return []logs.Entry{{Time: time.Now(), Source: logs.SourceFail2ban, Type: logs.TypeBan, Severity: logs.SevWarning,
		IP: "203.0.113.9", Fields: map[string]string{"jail": line}}}
}

func jails(es []logs.Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Fields["jail"])
	}
	return out
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func next(t *testing.T, s *Source) []string {
	t.Helper()
	es, _, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	return jails(es)
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSourceStartsAtEndAndReadsNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	appendFile(t, path, "antigo1\nantigo2\n")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	if got := next(t, s); got != nil {
		t.Fatalf("histórico deve ser ignorado: %v", got)
	}
	appendFile(t, path, "novo1\nnovo2\n")
	if got := next(t, s); !eq(got, []string{"novo1", "novo2"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSourcePartialLineWaitsForNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, path, "")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	next(t, s)
	appendFile(t, path, "meta")
	if got := next(t, s); got != nil {
		t.Fatalf("linha incompleta não pode sair: %v", got)
	}
	appendFile(t, path, "de\ninteira\n")
	if got := next(t, s); !eq(got, []string{"metade", "inteira"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSourceSameBatchUntilCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, path, "")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	next(t, s)
	appendFile(t, path, "a\nb\n")
	e1, id1, _ := s.Next()
	appendFile(t, path, "c\n")
	e2, id2, _ := s.Next()
	if id1 != id2 || len(e1) != 2 || len(e2) != 2 {
		t.Fatalf("o lote pendente deve ser repetido igual: %v %v %q %q", jails(e1), jails(e2), id1, id2)
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := next(t, s); !eq(got, []string{"c"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSourceResumesFromCommittedPositionAfterRestart(t *testing.T) {
	dir := t.TempDir()
	path, state := filepath.Join(dir, "app.log"), filepath.Join(dir, "state.json")
	appendFile(t, path, "")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState(state)}
	next(t, s)
	appendFile(t, path, "a\nb\n")
	if got := next(t, s); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "c\n")
	if got := next(t, s); !eq(got, []string{"c"}) { // lido, mas NÃO confirmado
		t.Fatalf("got %v", got)
	}
	s.Close() // "reinício" do agente sem confirmar "c"

	appendFile(t, path, "d\n")
	s2 := &Source{Path: path, Parser: linesParser{}, State: LoadState(state)}
	defer s2.Close()
	if got := next(t, s2); !eq(got, []string{"c", "d"}) {
		t.Fatalf("após reinício: %v", got)
	}
}

func TestSourceFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	appendFile(t, path, "")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	next(t, s)
	appendFile(t, path, "a\n")
	if got := next(t, s); !eq(got, []string{"a"}) {
		t.Fatal(got)
	}
	s.Commit()

	// linha escrita no arquivo antigo logo antes da rotação + arquivo novo
	appendFile(t, path, "b\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "c\nd\n")
	if got := next(t, s); !eq(got, []string{"b", "c", "d"}) {
		t.Fatalf("rotação: %v", got)
	}
}

func TestSourceHandlesTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, path, "")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	next(t, s)
	appendFile(t, path, "aaaaaaaa\nbbbbbbbb\n")
	next(t, s)
	s.Commit()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "x\n")
	if got := next(t, s); !eq(got, []string{"x"}) {
		t.Fatalf("copytruncate: %v", got)
	}
}

func TestSourceFileCreatedLaterIsReadFromStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "later.log")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	if got := next(t, s); got != nil {
		t.Fatal(got)
	}
	appendFile(t, path, "primeira\n")
	if got := next(t, s); !eq(got, []string{"primeira"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSourceTruncatesHugeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, path, "")
	s := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer s.Close()
	next(t, s)
	big := make([]byte, 100<<10)
	for i := range big {
		big[i] = 'x'
	}
	appendFile(t, path, string(big)+"\nfim\n")
	got := next(t, s)
	if len(got) != 2 || len(got[0]) != maxLineBytes || got[1] != "fim" {
		t.Fatalf("linhas: %d %d", len(got), len(got[0]))
	}
}

type fakeSender struct {
	errs  []error
	calls []logs.Batch
}

func (f *fakeSender) Do(_ context.Context, _, _ string, body, _ any) error {
	f.calls = append(f.calls, body.(logs.Batch))
	if len(f.errs) == 0 {
		return nil
	}
	err := f.errs[0]
	f.errs = f.errs[1:]
	return err
}

func TestShipperRetriesSameBatchAndDropsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	appendFile(t, path, "")
	src := &Source{Path: path, Parser: linesParser{}, State: LoadState("")}
	defer src.Close()
	snd := &fakeSender{errs: []error{errors.New("rede"), nil}}
	sh := &Shipper{Sources: []*Source{src}, Client: snd, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sh.Tick(context.Background()) // inicializa (fim do arquivo)
	appendFile(t, path, "a\n")

	sh.Tick(context.Background()) // falha transitória
	sh.Tick(context.Background()) // reenvia
	if len(snd.calls) != 2 || snd.calls[0].BatchID != snd.calls[1].BatchID {
		t.Fatalf("o reenvio deve repetir o batch_id: %+v", snd.calls)
	}
	sh.Tick(context.Background())
	if len(snd.calls) != 2 {
		t.Fatalf("lote confirmado não pode ser reenviado: %d chamadas", len(snd.calls))
	}

	snd.errs = []error{&agentclient.PermanentError{Status: 422, Code: "VALIDATION_ERROR"}}
	appendFile(t, path, "b\n")
	sh.Tick(context.Background())
	sh.Tick(context.Background())
	if len(snd.calls) != 3 {
		t.Fatalf("lote rejeitado (422) deve ser descartado, não repetido: %d chamadas", len(snd.calls))
	}

	snd.errs = []error{&agentclient.PermanentError{Status: 401}}
	appendFile(t, path, "c\n")
	sh.Tick(context.Background())
	sh.Tick(context.Background())
	if len(snd.calls) != 5 || snd.calls[3].BatchID != snd.calls[4].BatchID {
		t.Fatalf("erro de credencial deve manter o lote: %d chamadas", len(snd.calls))
	}
}

func TestLoadSettings(t *testing.T) {
	env := map[string]string{"SENTINELA_LOGS": "nginx, ufw", "STATE_DIRECTORY": "/var/lib/sentinela:/x", "SENTINELA_LOG_UFW_PATH": "/var/log/kern.log"}
	s, err := LoadSettings(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Sources) != 2 || s.Paths["ufw"] != "/var/log/kern.log" || s.StateFile != "/var/lib/sentinela/logtail.json" {
		t.Errorf("%+v", s)
	}
	if got := len(s.Build(nil)); got != 3 { // nginx_access, nginx_error, ufw
		t.Errorf("fontes: %d", got)
	}
	for _, bad := range []map[string]string{{"SENTINELA_LOGS": "apache"}, {"SENTINELA_LOGS": "ufw", "SENTINELA_LOG_UFW_PATH": "relativo.log"}} {
		if _, err := LoadSettings(func(k string) string { return bad[k] }); err == nil {
			t.Errorf("deveria rejeitar %v", bad)
		}
	}
	off, _ := LoadSettings(func(string) string { return "" })
	if len(off.Sources) != 0 {
		t.Error("sem SENTINELA_LOGS o recurso fica desativado")
	}
}
