// Package netutil reúne utilitários de rede compartilhados.
package netutil

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP devolve o IP do cliente. Só confia em X-Real-IP (definido pelo proxy
// reverso) quando trustProxy é verdadeiro; caso contrário usa o endereço da conexão.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(v) != nil {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IPv6PrefixBits é o tamanho da rede IPv6 tratada como uma única origem. Um /64 é a menor rede entregue a um
// cliente (provedores e nuvens costumam dar um /64 inteiro, ou mais), então quem tem um pode trocar de endereço
// à vontade: contar por endereço deixaria os limites inúteis.
const IPv6PrefixBits = 64

// Network devolve a rede que representa a origem do IP: o próprio endereço (/32) para IPv4, inclusive IPv4 mapeado em
// IPv6, e o /64 para IPv6. Inválido devolve um prefixo inválido.
func Network(ip string) netip.Prefix {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Prefix{}
	}
	a = a.Unmap().WithZone("")
	bits := 32
	if a.Is6() {
		bits = IPv6PrefixBits
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// LimitKey é a chave de origem para limites de taxa e de conexões: o endereço IPv4 ou a rede /64 do IPv6
// (ex.: "2001:db8:1:2::/64"). Texto que não é IP é devolvido como está.
func LimitKey(ip string) string {
	p := Network(ip)
	if !p.IsValid() {
		return ip
	}
	if p.Addr().Is4() {
		return p.Addr().String()
	}
	return p.String()
}
