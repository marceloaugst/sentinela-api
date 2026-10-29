package ipintel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxFetchPerCall  = 20 // consultas externas por chamada de Lookup; o resto é preenchido nas próximas
	fetchConcurrency = 5
	fetchBudget      = 4 * time.Second  // tempo máximo gasto na rede por chamada
	failureBackoff   = 10 * time.Minute // não repete logo um IP que falhou
)

// Service devolve Info de IPs usando o cache e consultando o AbuseIPDB só quando necessário.
type Service struct {
	Client     *Client
	TTL        time.Duration // validade do cache
	DailyLimit int
	Log        *slog.Logger
	Now        func() time.Time

	cache cache

	mu      sync.Mutex
	failed  map[string]time.Time // ip -> quando falhou
	blocked time.Time            // sem consultas externas até este instante (cota/chave)
}

func NewService(pool *pgxpool.Pool, c *Client, ttl time.Duration, dailyLimit int, log *slog.Logger) *Service {
	return &Service{Client: c, TTL: ttl, DailyLimit: dailyLimit, Log: log, cache: pgCache{pool}}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// IsPrivate informa se o IP não é roteável publicamente (não há o que consultar).
func IsPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast()
}

// Lookup devolve o que há de conhecido para cada IP (chave = IP normalizado). Nunca falha: erro de rede, cota
// esgotada ou banco indisponível só deixam o IP sem entrada (ou com a entrada vencida, que ainda é útil).
func (s *Service) Lookup(ctx context.Context, ips []string) map[string]Info {
	out := make(map[string]Info, len(ips))
	seen := make(map[string]bool, len(ips))
	var public []string
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if IsPrivate(ip) {
			out[ip] = Info{IP: ip, Private: true}
			continue
		}
		public = append(public, ip)
	}
	if len(public) == 0 {
		return out
	}
	cached, err := s.cache.Get(ctx, public)
	if err != nil {
		s.Log.Warn("cache de ip_intel indisponível", "err", err)
		return out
	}
	now := s.now()
	var stale []string
	for _, ip := range public {
		in, ok := cached[ip]
		if ok {
			out[ip] = in
		}
		if !ok || now.Sub(in.FetchedAt) > s.TTL {
			stale = append(stale, ip)
		}
	}
	if s.Client != nil && s.Client.Key != "" && len(stale) > 0 {
		s.refresh(ctx, stale, out)
	}
	return out
}

func (s *Service) refresh(ctx context.Context, ips []string, out map[string]Info) {
	now := s.now()
	s.mu.Lock()
	if now.Before(s.blocked) {
		s.mu.Unlock()
		return
	}
	todo := ips[:0:0]
	for _, ip := range ips {
		if t, ok := s.failed[ip]; ok && now.Sub(t) < failureBackoff {
			continue
		}
		if todo = append(todo, ip); len(todo) == maxFetchPerCall {
			break
		}
	}
	s.mu.Unlock()
	if len(todo) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, fetchBudget)
	defer cancel()
	var (
		wg  sync.WaitGroup
		rm  sync.Mutex // protege out
		sem = make(chan struct{}, fetchConcurrency)
	)
	for _, ip := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			in, ok := s.fetch(ctx, ip, now)
			if !ok {
				return
			}
			rm.Lock()
			out[ip] = in
			rm.Unlock()
		}()
	}
	wg.Wait()
}

func (s *Service) fetch(ctx context.Context, ip string, now time.Time) (Info, bool) {
	if s.isBlocked(now) {
		return Info{}, false
	}
	okQuota, err := s.cache.Reserve(ctx, now, s.DailyLimit)
	if err != nil {
		s.Log.Warn("cota de ip_intel indisponível", "err", err)
		return Info{}, false
	}
	if !okQuota {
		s.block(nextUTCDay(now))
		s.Log.Warn("limite diário de consultas ao AbuseIPDB atingido", "limit", s.DailyLimit)
		return Info{}, false
	}
	in, err := s.Client.Check(ctx, ip, now)
	switch {
	case errors.Is(err, ErrRateLimited):
		s.block(nextUTCDay(now))
		s.Log.Warn("AbuseIPDB recusou por excesso de consultas (429)")
		return Info{}, false
	case errors.Is(err, ErrUnauthorized):
		s.block(now.Add(time.Hour))
		s.Log.Error("AbuseIPDB rejeitou a chave (ABUSEIPDB_API_KEY)")
		return Info{}, false
	case err != nil:
		s.mu.Lock()
		if s.failed == nil {
			s.failed = map[string]time.Time{}
		}
		if len(s.failed) > 10000 {
			clear(s.failed)
		}
		s.failed[ip] = now
		s.mu.Unlock()
		s.Log.Warn("consulta ao AbuseIPDB falhou", "ip", ip, "err", err)
		return Info{}, false
	}
	if err := s.cache.Put(ctx, in); err != nil {
		s.Log.Warn("não foi possível guardar ip_intel", "err", err)
	}
	return in, true
}

func (s *Service) isBlocked(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.blocked)
}

func (s *Service) block(until time.Time) {
	s.mu.Lock()
	s.blocked = until
	s.mu.Unlock()
}

func nextUTCDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
}
