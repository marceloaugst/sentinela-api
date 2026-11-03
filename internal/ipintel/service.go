package ipintel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"sentinela/internal/ratelimit"
)

const (
	maxFetchPerCall  = 20 // consultas externas por chamada de Lookup; o resto é preenchido nas próximas
	fetchConcurrency = 5
	fetchBudget      = 4 * time.Second  // tempo máximo gasto na rede por chamada
	failureBackoff   = 10 * time.Minute // não repete logo um IP que falhou
)

// DefaultHourlyLimit é o teto de consultas externas por hora quando HourlyLimit não é definido: 1/12 da cota diária
// (83 de 1000), com no mínimo 10 (ou a própria cota diária, se menor). Assim a cota não se esgota em poucos minutos.
func DefaultHourlyLimit(daily int) int { return max(daily/12, min(daily, 10), 1) }

// Service devolve Info de IPs usando o cache e consultando o AbuseIPDB só quando necessário.
type Service struct {
	Client     *Client
	TTL        time.Duration // validade do cache
	DailyLimit int
	// HourlyLimit é o teto de consultas externas por hora, por instância (0 = DefaultHourlyLimit). Quem lê logs dispara
	// consultas de IPs ainda não vistos (e um agente comprometido pode inventar IPs): sem este teto, algumas dezenas de
	// telas esgotariam a cota diária e o recurso ficaria parado até 00:00 UTC.
	HourlyLimit int
	Log         *slog.Logger
	Now         func() time.Time

	cache cache

	mu      sync.Mutex
	failed  map[string]time.Time // ip -> quando falhou
	blocked time.Time            // sem consultas externas até este instante (cota/chave)

	hourly       *ratelimit.Limiter // criado no primeiro uso, a partir de HourlyLimit
	hourlyWarned time.Time          // último aviso de teto por hora atingido (evita um log por consulta negada)
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

// nonPublic são as faixas reservadas que o netip não classifica como privadas, mas que não são endereços públicos
// de ninguém (IANA special-purpose registries): não há reputação a consultar e o IP não deve ser enviado a terceiros.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8",       // "esta rede"
		"100.64.0.0/10",   // CGNAT (RFC 6598): IPs de operadoras, repetidos entre clientes
		"192.0.0.0/24",    // atribuições do protocolo IETF
		"192.0.2.0/24",    // documentação (TEST-NET-1)
		"192.88.99.0/24",  // relay 6to4 (obsoleto)
		"198.18.0.0/15",   // testes de desempenho
		"198.51.100.0/24", // documentação (TEST-NET-2)
		"203.0.113.0/24",  // documentação (TEST-NET-3)
		"240.0.0.0/4",     // reservado (inclui 255.255.255.255)
		"64:ff9b::/96",    // NAT64: traduz um IPv4, não é um host
		"64:ff9b:1::/48",  // NAT64 de uso local
		"100::/64",        // descarte
		"2001::/23",       // atribuições do protocolo IETF (Teredo, ORCHID...)
		"2001:db8::/32",   // documentação
		"3fff::/20",       // documentação
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// IsPrivate informa se o IP não é um endereço público: privado, loopback, link-local, multicast, não especificado ou de
// faixa reservada (CGNAT, documentação, testes...). Não há o que consultar e nada é enviado a terceiros. Texto que não é
// IP devolve false (Lookup o ignora por outro caminho).
func IsPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("") // ::ffff:10.0.0.1 vale como 10.0.0.1
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return true
		}
	}
	return false
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
		if _, err := netip.ParseAddr(ip); err != nil {
			continue // o que não é IP nunca vai ao banco nem à rede
		}
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
	// O teto por hora vem ANTES da cota diária: uma consulta negada aqui não gasta a cota do dia.
	if !s.allowHourly(now) {
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

// allowHourly consome uma consulta do teto por hora. Ao negar, avisa no log (no máximo a cada 10 minutos).
func (s *Service) allowHourly(now time.Time) bool {
	s.mu.Lock()
	if s.hourly == nil {
		n := s.HourlyLimit
		if n <= 0 {
			n = DefaultHourlyLimit(s.DailyLimit)
		}
		s.hourly = ratelimit.New(float64(n)/3600, n) // enche de novo em 1 hora
	}
	l := s.hourly
	s.mu.Unlock()
	if ok, _ := l.Allow("abuseipdb"); ok {
		return true
	}
	s.mu.Lock()
	warn := now.Sub(s.hourlyWarned) >= 10*time.Minute
	if warn {
		s.hourlyWarned = now
	}
	s.mu.Unlock()
	if warn {
		s.Log.Warn("teto de consultas por hora ao AbuseIPDB atingido; novos IPs ficam sem geolocalização por enquanto")
	}
	return false
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
