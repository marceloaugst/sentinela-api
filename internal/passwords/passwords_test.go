package passwords

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var light = Params{MemoryKiB: 256, Time: 1, Threads: 1} // só para os testes ficarem rápidos
var ctx = context.Background()

func TestHashFormatSaltAndVerify(t *testing.T) {
	h := NewHasher(light, 2)
	a, err := h.Hash(ctx, "uma senha bem longa 123")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := h.Hash(ctx, "uma senha bem longa 123")
	if a == b {
		t.Error("o salt deve ser aleatório: mesmo texto, hashes diferentes")
	}
	if !strings.HasPrefix(a, "$argon2id$v=19$m=256,t=1,p=1$") || strings.Contains(a, "uma senha") {
		t.Errorf("formato: %s", a)
	}
	if ok, rehash, err := h.Verify(ctx, "uma senha bem longa 123", a); !ok || rehash || err != nil {
		t.Errorf("verificação correta: %v %v %v", ok, rehash, err)
	}
	for _, wrong := range []string{"outra senha bem longa", "", "uma senha bem longa 124", strings.ToUpper("uma senha bem longa 123")} {
		if ok, _, _ := h.Verify(ctx, wrong, a); ok {
			t.Errorf("%q não deveria validar", wrong)
		}
	}
}

func TestNeedsRehashWhenParametersAreWeaker(t *testing.T) {
	weak := NewHasher(Params{MemoryKiB: 64, Time: 1, Threads: 1}, 1)
	strong := NewHasher(Params{MemoryKiB: 256, Time: 2, Threads: 1}, 1)
	old, _ := weak.Hash(ctx, "senha-antiga-correta")
	ok, rehash, err := strong.Verify(ctx, "senha-antiga-correta", old)
	if !ok || !rehash || err != nil {
		t.Errorf("hash fraco deve validar e pedir rehash: %v %v %v", ok, rehash, err)
	}
	cur, _ := strong.Hash(ctx, "senha-antiga-correta")
	if ok, rehash, _ := strong.Verify(ctx, "senha-antiga-correta", cur); !ok || rehash {
		t.Errorf("hash atual não pede rehash: %v %v", ok, rehash)
	}
	// um hash MAIS forte que o atual também valida (parâmetros vêm do próprio hash)
	if ok, rehash, _ := weak.Verify(ctx, "senha-antiga-correta", cur); !ok || rehash {
		t.Errorf("hash forte: %v %v", ok, rehash)
	}
}

func TestVerifyRejectsMalformedAndDangerousHashes(t *testing.T) {
	h := NewHasher(light, 1)
	good, _ := h.Hash(ctx, "x")
	bad := []string{
		"", "texto", "$argon2i$v=19$m=256,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=18$m=256,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=999999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // memória absurda: DoS
		"$argon2id$v=19$m=256,t=9999,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",    // tempo absurdo
		"$argon2id$v=19$m=256,t=1,p=255$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=256,t=1,p=1$$", "$argon2id$v=19$m=256,t=1,p=1$!!!$???",
		strings.Replace(good, "$argon2id", "$argon2id$extra", 1),
	}
	for _, e := range bad {
		if ok, _, err := h.Verify(ctx, "x", e); ok || err == nil {
			t.Errorf("%q deveria ser recusado com erro (ok=%v err=%v)", e, ok, err)
		}
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	h := NewHasher(Params{MemoryKiB: 4096, Time: 2, Threads: 1}, 2)
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.acquire(ctx); err != nil {
				t.Error(err)
				return
			}
			c := running.Add(1)
			for {
				p := peak.Load()
				if c <= p || peak.CompareAndSwap(p, c) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			running.Add(-1)
			h.release()
		}()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Errorf("simultâneos: %d (limite 2)", peak.Load())
	}
	// contexto cancelado não fica preso esperando vaga
	h.sem <- struct{}{}
	h.sem <- struct{}{}
	c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(c, "x"); err == nil {
		t.Error("deveria respeitar o contexto")
	}
}

func TestDummyVerifyTakesComparableTimeToARealVerify(t *testing.T) {
	h := NewHasher(Params{MemoryKiB: 8192, Time: 2, Threads: 1}, 1)
	real, _ := h.Hash(ctx, "senha-real-12345")
	measure := func(f func()) time.Duration {
		best := time.Hour
		for i := 0; i < 5; i++ {
			s := time.Now()
			f()
			if d := time.Since(s); d < best {
				best = d
			}
		}
		return best
	}
	r := measure(func() { h.Verify(ctx, "errada-errada-12", real) })
	d := measure(func() { h.DummyVerify(ctx, "errada-errada-12") })
	ratio := float64(d) / float64(r)
	if ratio < 0.6 || ratio > 1.6 {
		t.Errorf("tempos diferentes demais (revelaria e-mails existentes): real=%v dummy=%v", r, d)
	}
}

func TestPolicy(t *testing.T) {
	ok := []string{"correct horse battery staple", "Xk9#mQ2$vL7!pR4z", "uma frase longa e fácil de lembrar"}
	for _, p := range ok {
		if msgs := Validate(p, "ana.silva@exemplo.com", "Ana Silva"); len(msgs) != 0 {
			t.Errorf("%q deveria ser aceita: %v", p, msgs)
		}
	}
	bad := map[string]string{
		"curta1!":                   "curta",
		"":                          "vazia",
		strings.Repeat("a", 129):    "longa demais",
		"password1234":              "comum",
		"Password123!":              "comum",
		"qwertyuiop":                "comum e curta",
		"aaaaaaaaaaaaaa":            "repetição",
		"abcdefghijklm":             "sequência",
		"9876543210987":             "sequência",
		" espaços nas pontas ok ":   "espaço nas pontas",
		"ana.silva-2026-segura":     "contém o e-mail",
		"minha-silva-super-forte-1": "contém o nome",
		"Sentinela2026!":            "comum (nome do produto)",
	}
	for p, why := range bad {
		if msgs := Validate(p, "ana.silva@exemplo.com", "Ana Silva"); len(msgs) == 0 {
			t.Errorf("%q (%s) deveria ser recusada", p, why)
		}
	}
	// comprimento conta caracteres, não bytes
	if msgs := Validate(strings.Repeat("ç", 12)+"x1", "a@b.com", "x"); len(msgs) != 0 {
		t.Logf("repetição de ç: %v", msgs)
	}
}
