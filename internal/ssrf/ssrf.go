// Package ssrf impede que verificações iniciadas pela API alcancem redes internas,
// metadados de nuvem e outros destinos sensíveis (Server-Side Request Forgery).
//
// A defesa principal é aplicada no momento da CONEXÃO (net.Dialer.Control), sobre o IP já
// resolvido: isso cobre DNS que aponta para IP interno e DNS rebinding. A validação da URL
// no cadastro é apenas a primeira barreira, para dar erro cedo.
package ssrf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
)

var ErrBlocked = errors.New("destino bloqueado pela política de segurança")

// Faixas bloqueadas além das que o pacote netip já classifica (loopback, privado, link-local, multicast...).
var extraBlocked = mustPrefixes(
	"0.0.0.0/8",       // "esta rede"
	"100.64.0.0/10",   // CGNAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentação
	"192.88.99.0/24",  // 6to4 relay (obsoleto)
	"198.18.0.0/15",   // benchmark
	"198.51.100.0/24", // documentação
	"203.0.113.0/24",  // documentação
	"240.0.0.0/4",     // reservado (inclui broadcast)
	"64:ff9b::/96",    // NAT64
	"100::/64",        // discard
	"2001:db8::/32",   // documentação
	"2002::/16",       // 6to4
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

type Policy struct {
	// Allowed lista CIDRs explicitamente autorizados pelo operador (ex.: um serviço interno
	// legítimo). Têm precedência sobre os bloqueios. Vazio por padrão.
	Allowed []netip.Prefix
}

// ParseAllowed converte "10.0.5.0/24,192.168.1.10/32" em prefixos.
func ParseAllowed(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("CIDR inválido %q", part)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// CheckAddr devolve ErrBlocked se o endereço não pode ser alvo de verificações.
func (p Policy) CheckAddr(a netip.Addr) error {
	a = a.Unmap() // ::ffff:10.0.0.1 deve ser tratado como 10.0.0.1
	for _, pre := range p.Allowed {
		if pre.Contains(a) {
			return nil
		}
	}
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return ErrBlocked
	}
	for _, pre := range extraBlocked {
		if pre.Contains(a) {
			return ErrBlocked
		}
	}
	return nil
}

var blockedHostSuffixes = []string{".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet"}

// ValidateURL aplica as regras estáticas: só http/https, sem credenciais embutidas, porta
// válida e host que não seja um nome interno nem um IP literal bloqueado.
// Não resolve DNS (evita usar o cadastro como sonda); a resolução é checada na conexão.
func (p Policy) ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("URL inválida")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("somente http e https são permitidos")
	}
	if u.User != nil {
		return nil, errors.New("URL não pode conter usuário/senha")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("porta inválida")
		}
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return nil, errors.New("URL sem host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if p.CheckAddr(addr) != nil {
			return nil, errors.New("endereço IP não permitido")
		}
		return u, nil
	}
	if !strings.Contains(host, ".") || host == "localhost" {
		return nil, errors.New("host interno não permitido")
	}
	for _, s := range blockedHostSuffixes {
		if strings.HasSuffix(host, s) {
			return nil, errors.New("host interno não permitido")
		}
	}
	if host == "metadata.google.internal" {
		return nil, errors.New("host interno não permitido")
	}
	return u, nil
}

// Control é usado em net.Dialer.Control: roda após a resolução DNS, imediatamente antes
// de conectar, com o IP real. address tem a forma "ip:porta".
func (p Policy) Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		host, _, e2 := net.SplitHostPort(address)
		if e2 != nil {
			return ErrBlocked
		}
		a, e3 := netip.ParseAddr(host)
		if e3 != nil {
			return ErrBlocked
		}
		return p.CheckAddr(a)
	}
	return p.CheckAddr(ap.Addr())
}
