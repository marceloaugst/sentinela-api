package dockerhost

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultSocket é o socket padrão do daemon.
const DefaultSocket = "/var/run/docker.sock"

const (
	maxInspected = 30       // containers inativos com erro e log detalhados por relatório
	logLines     = 15       // linhas de log do fim
	maxLogRead   = 64 << 10 // bytes lidos do log antes de cortar
	maxJSON      = 4 << 20
)

// Client fala com a API HTTP do daemon pelo socket Unix. Só estas chamadas existem: listar, inspecionar,
// ler o fim do log, iniciar e reiniciar. Nada que o Docker aceite além disso é alcançável por aqui.
type Client struct {
	Socket string
	HTTP   *http.Client
}

func NewClient(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	return &Client{Socket: socket, HTTP: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}}}
}

// Detect diz se há Docker neste host e se o agente consegue usá-lo: ok, not_installed, no_access ou unavailable.
func (c *Client) Detect(ctx context.Context) (status, msg string) {
	if _, err := os.Stat(c.Socket); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return StatusNotInstalled, "Docker não encontrado neste servidor (sem " + c.Socket + ")."
		}
		if errors.Is(err, fs.ErrPermission) {
			return StatusNoAccess, noAccessMsg
		}
		return StatusUnavailable, "Não foi possível verificar o socket do Docker: " + errText(err)
	}
	var v struct{ Version string }
	if err := c.getJSON(ctx, "/version", &v); err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EACCES):
			return StatusNoAccess, noAccessMsg
		case errors.Is(err, fs.ErrNotExist): // socket sumiu entre o Stat e a conexão
			return StatusNotInstalled, "Docker não encontrado neste servidor (sem " + c.Socket + ")."
		}
		return StatusUnavailable, "O Docker está instalado, mas não respondeu: " + errText(err)
	}
	return StatusOK, ""
}

const noAccessMsg = "O Docker está instalado, mas o agente não tem permissão no socket. Rode deploy/update.sh --docker (ou adicione o agente ao grupo docker; veja docs/agent.md)."

func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return clean(err.Error(), 200, false)
}

// Snapshot monta o relatório: todos os containers e, para os inativos, o erro e o fim do log.
func (c *Client) Snapshot(ctx context.Context, now time.Time) Report {
	rep := Report{CheckedAt: now.UTC(), Containers: []Container{}}
	rep.Status, rep.Message = c.Detect(ctx)
	if rep.Status != StatusOK {
		return rep
	}
	list, err := c.List(ctx)
	if err != nil {
		rep.Status, rep.Message = StatusUnavailable, "Falha ao listar containers: "+errText(err)
		return rep
	}
	if len(list) > MaxContainers {
		list = list[:MaxContainers]
	}
	detailed := 0
	for i := range list {
		ct := &list[i]
		if Active(ct.State) || ct.State == "paused" || detailed >= maxInspected {
			continue
		}
		detailed++
		c.fillInactive(ctx, ct)
	}
	rep.Containers = list
	return rep
}

type listItem struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

// List devolve os containers (todos os estados) sem detalhes de erro nem log.
func (c *Client) List(ctx context.Context) ([]Container, error) {
	var items []listItem
	if err := c.getJSON(ctx, "/containers/json?all=1", &items); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(items))
	for _, it := range items {
		name := it.ID
		if len(it.Names) > 0 {
			name = strings.TrimPrefix(it.Names[0], "/")
		}
		out = append(out, Container{ID: it.ID, Name: name, Image: it.Image, State: it.State, Status: it.Status})
	}
	return out, nil
}

type inspect struct {
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		OOMKilled  bool   `json:"OOMKilled"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
	Config struct {
		Tty bool `json:"Tty"`
	} `json:"Config"`
}

func (c *Client) inspect(ctx context.Context, id string) (inspect, error) {
	var in inspect
	err := c.getJSON(ctx, "/containers/"+id+"/json", &in)
	return in, err
}

// fillInactive acrescenta ao container inativo o motivo (código de saída, erro do Docker, OOM) e o fim do log.
func (c *Client) fillInactive(ctx context.Context, ct *Container) {
	ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	in, err := c.inspect(ictx, ct.ID)
	if err != nil {
		ct.Error = "Não foi possível ler os detalhes do container: " + errText(err)
		return
	}
	code := in.State.ExitCode
	if ct.State != "created" {
		ct.ExitCode = &code
	}
	ct.OOMKilled = in.State.OOMKilled
	ct.StartedAt, ct.FinishedAt = parseTime(in.State.StartedAt), parseTime(in.State.FinishedAt)
	ct.Error = Explain(ct.State, code, in.State.OOMKilled, in.State.Error)
	if ct.State == "created" {
		return // nunca rodou: não há log
	}
	if tail, err := c.logTail(ictx, ct.ID, in.Config.Tty); err == nil {
		ct.LogTail = clean(tail, maxLogTail, true)
	}
}

// Explain traduz o estado de saída em uma frase para a tela.
func Explain(state string, code int, oom bool, dockerErr string) string {
	switch {
	case strings.TrimSpace(dockerErr) != "":
		return "Erro do Docker: " + strings.TrimSpace(dockerErr)
	case oom:
		return "Encerrado por falta de memória (OOM killer), código " + strconv.Itoa(code) + "."
	case state == "created":
		return "Criado, mas nunca iniciado."
	case state == "dead":
		return "Container em estado dead (falha ao ser removido)."
	case code == 0:
		return "Encerrou normalmente (código 0)."
	case code > 128:
		return fmt.Sprintf("Encerrado pelo sinal %d (código %d).", code-128, code)
	}
	return "Saiu com erro, código " + strconv.Itoa(code) + "."
}

func parseTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 { // "0001-01-01T00:00:00Z" = nunca
		return nil
	}
	return &t
}

func (c *Client) logTail(ctx context.Context, id string, tty bool) (string, error) {
	resp, err := c.do(ctx, "GET", "/containers/"+id+"/logs?stdout=1&stderr=1&tail="+strconv.Itoa(logLines))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp)
	}
	if tty {
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxLogRead))
		return string(b), err
	}
	return demux(io.LimitReader(resp.Body, maxLogRead)), nil
}

// demux separa o fluxo multiplexado do Docker (cabeçalho de 8 bytes: tipo, 3 zeros, tamanho big-endian).
func demux(r io.Reader) string {
	var sb strings.Builder
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return sb.String()
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 || n > maxLogRead {
			return sb.String()
		}
		if _, err := io.CopyN(&sb, r, int64(n)); err != nil {
			return sb.String()
		}
	}
}

// Start inicia o container (já iniciado também conta como sucesso).
func (c *Client) Start(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+id+"/start")
}

// Restart reinicia o container (10 s de tolerância antes do SIGKILL).
func (c *Client) Restart(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+id+"/restart?t=10")
}

// Settled lê o estado depois de uma ação: se o container não ficou ativo, devolve o motivo.
func (c *Client) Settled(ctx context.Context, id string) (running bool, why string, err error) {
	in, err := c.inspect(ctx, id)
	if err != nil {
		return false, "", err
	}
	if in.State.Running {
		return true, "", nil
	}
	return false, Explain(in.State.Status, in.State.ExitCode, in.State.OOMKilled, in.State.Error), nil
}

func (c *Client) post(ctx context.Context, path string) error {
	resp, err := c.do(ctx, "POST", path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	return apiError(resp)
}

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	return c.HTTP.Do(req)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, "GET", path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError(resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSON)).Decode(out)
}

// apiError devolve a mensagem que o Docker mandou ({"message": "..."}) ou o código HTTP.
func apiError(resp *http.Response) error {
	var body struct {
		Message string `json:"message"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if json.Unmarshal(b, &body) == nil && body.Message != "" {
		return errors.New(clean(body.Message, 250, false))
	}
	return fmt.Errorf("o Docker respondeu HTTP %d", resp.StatusCode)
}
