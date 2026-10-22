package logtail

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"sentinela/internal/logs"
)

const (
	maxLineBytes = 16 << 10 // linhas maiores são truncadas (o resto é descartado)
	maxBatch     = 200
	maxLinesRead = 2000 // por rodada, para não monopolizar o agente
)

// Position identifica um ponto confirmado num arquivo (inode + deslocamento), imune à rotação.
type Position struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// State persiste as posições confirmadas por caminho. Com Path vazio, fica só em memória.
type State struct {
	Path string
	mu   sync.Mutex
	pos  map[string]Position
}

func LoadState(path string) *State {
	s := &State{Path: path, pos: map[string]Position{}}
	if path == "" {
		return s
	}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &s.pos) // arquivo corrompido: recomeça do fim dos logs
		if s.pos == nil {
			s.pos = map[string]Position{}
		}
	}
	return s
}

func (s *State) get(file string) (Position, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pos[file]
	return p, ok
}

func (s *State) set(file string, p Position) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pos[file] = p
	if s.Path == "" {
		return nil
	}
	raw, err := json.Marshal(s.pos)
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Source acompanha UM arquivo de log (como `tail -F`): sobrevive à rotação e nunca perde nem repete
// linhas confirmadas. Next devolve o mesmo lote até Commit ser chamado.
type Source struct {
	Name   string // rótulo para logs do agente
	Path   string
	Parser Parser
	State  *State
	// FromStart lê o arquivo desde o início quando não há posição salva (padrão: começa no fim).
	FromStart bool
	Now       func() time.Time

	f           *os.File
	r           *bufio.Reader
	inode       uint64
	off         int64 // deslocamento após a última linha completa
	raw         int64 // bytes lidos da linha em andamento (ainda sem \n)
	partial     []byte
	seenMissing bool

	pending   []logs.Entry
	pendingID string
	pendingTo Position
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Close libera o arquivo aberto.
func (s *Source) Close() {
	if s.f != nil {
		s.f.Close()
		s.f, s.r = nil, nil
	}
}

func (s *Source) open(resume bool) error {
	f, err := os.Open(s.Path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	ino := inodeOf(fi)
	var off int64
	if resume {
		if saved, ok := s.State.get(s.Path); ok {
			if saved.Inode == ino && saved.Offset <= fi.Size() {
				off = saved.Offset
			} // senão: o arquivo foi rotacionado/truncado com o agente parado; lê o novo desde o início
		} else if !s.FromStart && !s.seenMissing {
			off = fi.Size() // primeira execução: ignora o histórico
		}
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	s.Close()
	s.f, s.r, s.inode, s.off, s.raw, s.partial = f, bufio.NewReaderSize(f, 64<<10), ino, off, 0, nil
	return nil
}

// Next devolve o lote pendente ou lê novas linhas. Devolve (nil, "") quando não há nada novo.
func (s *Source) Next() ([]logs.Entry, string, error) {
	if s.pending != nil {
		return s.pending, s.pendingID, nil
	}
	if s.f == nil {
		if err := s.open(true); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				s.seenMissing = true // quando surgir, lê desde o início
				return nil, "", nil
			}
			return nil, "", err
		}
	}
	var out []logs.Entry
	lines := 0
	for lines < maxLinesRead && len(out) < maxBatch {
		line, err := s.readLine()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, "", err
			}
			// EOF: se o caminho agora aponta para outro arquivo (rotação), troca depois de esgotar este.
			rotated, rerr := s.rotated()
			if rerr != nil {
				return nil, "", rerr
			}
			if rotated {
				if oerr := s.open(false); oerr != nil {
					return nil, "", oerr
				}
				continue
			}
			break
		}
		lines++
		out = append(out, s.Parser.Parse(line)...)
	}
	out = append(out, s.Parser.Idle(s.now())...)
	s.pendingTo = Position{Inode: s.inode, Offset: s.off}
	if len(out) == 0 {
		// nada a enviar, mas o progresso (linhas ignoradas) precisa ser salvo
		if saved, ok := s.State.get(s.Path); !ok || saved != s.pendingTo {
			if err := s.State.set(s.Path, s.pendingTo); err != nil {
				return nil, "", err
			}
		}
		return nil, "", nil
	}
	s.pending, s.pendingID = out, newBatchID()
	return s.pending, s.pendingID, nil
}

// Commit confirma o lote devolvido por Next e persiste a posição.
func (s *Source) Commit() error {
	if s.pending == nil {
		return nil
	}
	s.pending, s.pendingID = nil, ""
	return s.State.set(s.Path, s.pendingTo)
}

// rotated informa se o caminho agora é outro arquivo (inode diferente) ou foi truncado.
func (s *Source) rotated() (bool, error) {
	fi, err := os.Stat(s.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // entre a rotação e a recriação; mantém o descritor antigo
		}
		return false, err
	}
	if inodeOf(fi) != s.inode && inodeOf(fi) != 0 {
		return true, nil
	}
	return fi.Size() < s.off+s.raw, nil // truncado (copytruncate)
}

// readLine devolve uma linha COMPLETA (terminada em \n). Uma linha incompleta no EOF fica em s.partial
// e é completada na próxima chamada; o deslocamento confirmado (s.off) só avança em linhas completas.
func (s *Source) readLine() (string, error) {
	for {
		chunk, err := s.r.ReadSlice('\n')
		if room := maxLineBytes - len(s.partial); room > 0 {
			s.partial = append(s.partial, chunk[:min(len(chunk), room)]...)
		}
		s.raw += int64(len(chunk))
		switch {
		case err == nil:
			line := trimEOL(string(s.partial))
			s.partial = s.partial[:0]
			s.off += s.raw
			s.raw = 0
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", err // inclui io.EOF; o trecho incompleto é mantido
		}
	}
}

func trimEOL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func newBatchID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
