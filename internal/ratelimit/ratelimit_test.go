package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(1, 3)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("requisição %d dentro do burst foi negada", i)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Second {
		t.Fatalf("4ª deveria ser negada com retry <= 1s: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Error("chaves independentes não devem interferir")
	}
	now = now.Add(1500 * time.Millisecond)
	if ok, _ := l.Allow("a"); !ok {
		t.Error("após 1,5s deveria haver 1 token")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Error("só 1 token foi reposto")
	}
}

func TestLimiterSweepBoundsMemory(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(1, 2)
	l.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		l.Allow(string(rune('a' + i)))
	}
	now = now.Add(5 * time.Minute)
	l.Allow("novo")
	if n := l.size(); n != 1 {
		t.Errorf("baldes antigos deveriam ser removidos, restaram %d", n)
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := New(0.0001, 50) // praticamente sem reposição
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if ok, _ := l.Allow("k"); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 50 {
		t.Errorf("permitidas = %d, esperado exatamente o burst (50)", got)
	}
}
