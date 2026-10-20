// Package ratelimit implementa limitação de taxa por chave (token bucket) em memória.
//
// Limitação: o estado é por instância. Com várias instâncias da API o limite efetivo é multiplicado pelo
// número de instâncias; um limite global exigiria um armazenamento compartilhado (ex.: Redis).
package ratelimit

import (
	"sync"
	"time"
)

// Limiter é um token bucket por chave, seguro para uso concorrente.
type Limiter struct {
	rate  float64 // tokens por segundo
	burst float64
	now   func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(ratePerSecond float64, burst int) *Limiter {
	return &Limiter{rate: ratePerSecond, burst: float64(burst), now: time.Now, buckets: map[string]*bucket{}}
}

// Allow consome um token. Quando negado, retry indica quando tentar novamente.
func (l *Limiter) Allow(key string) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	need := (1 - b.tokens) / l.rate
	return false, time.Duration(need * float64(time.Second))
}

// sweep remove baldes que já estariam cheios (equivalentes a uma chave nova),
// limitando o uso de memória. Chamado com o lock mantido.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) > full {
			delete(l.buckets, k)
		}
	}
}

func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
