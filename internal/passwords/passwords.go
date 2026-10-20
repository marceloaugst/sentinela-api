// Package passwords faz o hash (Argon2id) e a política de senhas.
package passwords

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Params segue a recomendação da OWASP para Argon2id (m=19 MiB, t=2, p=1 é o mínimo); o padrão é
// mais forte. Os parâmetros ficam DENTRO do hash, então podem ser elevados no futuro e as senhas
// antigas são reprocessadas no próximo login (NeedsRehash).
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

var Default = Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2}

const (
	keyLen  = 32
	saltLen = 16
	// limites aceitos ao LER um hash do banco (um hash adulterado não pode causar negação de serviço)
	maxMemoryKiB = 512 * 1024
	maxTime      = 12
	maxThreads   = 16
)

var ErrInvalidHash = errors.New("hash de senha inválido")

// Hasher limita quantos hashes rodam ao mesmo tempo: cada Argon2id usa dezenas de MiB e um surto de
// logins não pode esgotar a memória do processo.
type Hasher struct {
	P     Params
	sem   chan struct{}
	dummy string
}

func NewHasher(p Params, maxConcurrent int) *Hasher {
	if p.MemoryKiB == 0 {
		p = Default
	}
	if maxConcurrent < 1 {
		maxConcurrent = 4
	}
	h := &Hasher{P: p, sem: make(chan struct{}, maxConcurrent)}
	h.dummy, _ = h.hash("senha-fantasma-para-igualar-o-tempo", p)
	return h
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

func (h *Hasher) hash(plain string, p Params) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(plain), salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// Hash gera o hash PHC ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func (h *Hasher) Hash(ctx context.Context, plain string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.hash(plain, h.P)
}

func parse(encoded string) (p Params, salt, sum []byte, err error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return p, nil, nil, ErrInvalidHash
	}
	var m, t uint32
	var th uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if m < 8 || m > maxMemoryKiB || t < 1 || t > maxTime || th < 1 || th > maxThreads {
		return p, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) < 8 {
		return p, nil, nil, ErrInvalidHash
	}
	if sum, err = b64.DecodeString(parts[5]); err != nil || len(sum) < 16 {
		return p, nil, nil, ErrInvalidHash
	}
	return Params{MemoryKiB: m, Time: t, Threads: th}, salt, sum, nil
}

// Verify compara em tempo constante. needsRehash indica que o hash usa parâmetros mais fracos que os atuais.
func (h *Hasher) Verify(ctx context.Context, plain, encoded string) (ok, needsRehash bool, err error) {
	p, salt, want, err := parse(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(plain), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	ok = subtle.ConstantTimeCompare(got, want) == 1
	needsRehash = ok && (p.MemoryKiB < h.P.MemoryKiB || p.Time < h.P.Time || p.Threads < h.P.Threads)
	return ok, needsRehash, nil
}

// DummyVerify gasta o mesmo tempo de uma verificação real. Usado quando o usuário não existe, para que
// o tempo de resposta não revele quais e-mails estão cadastrados.
func (h *Hasher) DummyVerify(ctx context.Context, plain string) {
	_, _, _ = h.Verify(ctx, plain, h.dummy)
}

// ---- política ----

const (
	MinLength = 12
	MaxLength = 128
)

var commonBases = map[string]bool{
	"password": true, "senha": true, "qwerty": true, "qwertyuiop": true, "admin": true, "administrador": true,
	"letmein": true, "welcome": true, "changeme": true, "sentinela": true, "monitor": true, "iloveyou": true,
	"abc": true, "abcdef": true, "abcdefgh": true, "abcd": true, "master": true, "login": true, "passw0rd": true,
	"trustno": true, "dragon": true, "football": true, "mudar": true, "mudar123": true, "brasil": true,
	"12345678": true, "123456789": true, "1234567890": true, "0123456789": true, "123456": true,
}

// Validate devolve as mensagens de problema (vazio = aceita). Prioriza comprimento sobre complexidade
// (NIST SP 800-63B) e recusa senhas óbvias ou derivadas do e-mail/nome.
func Validate(pw, email, name string) []string {
	var out []string
	n := utf8.RuneCountInString(pw)
	switch {
	case n < MinLength:
		out = append(out, fmt.Sprintf("deve ter pelo menos %d caracteres", MinLength))
	case n > MaxLength:
		out = append(out, fmt.Sprintf("deve ter no máximo %d caracteres", MaxLength))
	}
	if len(out) > 0 {
		return out
	}
	if strings.TrimSpace(pw) != pw {
		out = append(out, "não pode começar nem terminar com espaço")
	}
	low := strings.ToLower(pw)
	// "Password123!" é só "password" com enfeites: apara dígitos e símbolos do fim, em qualquer ordem
	stripped := strings.TrimRightFunc(low, func(r rune) bool { return unicode.IsDigit(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) })
	if commonBases[low] || commonBases[stripped] {
		out = append(out, "é uma senha muito comum")
	}
	if allSame(pw) || isSequence(low) {
		out = append(out, "não pode ser uma repetição ou sequência simples")
	}
	if local, _, ok := strings.Cut(strings.ToLower(email), "@"); ok && len(local) >= 4 && strings.Contains(low, local) {
		out = append(out, "não pode conter o seu e-mail")
	}
	for _, w := range strings.Fields(strings.ToLower(name)) {
		if len(w) >= 4 && strings.Contains(low, w) {
			out = append(out, "não pode conter o seu nome")
			break
		}
	}
	return out
}

func allSame(s string) bool {
	r := []rune(s)
	for _, c := range r {
		if c != r[0] {
			return false
		}
	}
	return len(r) > 0
}

func isSequence(s string) bool {
	r := []rune(s)
	if len(r) < 8 {
		return false
	}
	up, down, allDigits := true, true, true
	for i, c := range r {
		if !unicode.IsDigit(c) {
			allDigits = false
		}
		if i == 0 {
			continue
		}
		if r[i] != r[i-1]+1 {
			up = false
		}
		if r[i] != r[i-1]-1 {
			down = false
		}
	}
	if up || down {
		return true
	}
	if allDigits { // 7890123456 também é sequência: os dígitos dão a volta no 0
		up, down = true, true
		for i := 1; i < len(r); i++ {
			d := int(r[i]-'0') - int(r[i-1]-'0')
			if d != 1 && d != -9 {
				up = false
			}
			if d != -1 && d != 9 {
				down = false
			}
		}
		return up || down
	}
	return false
}
