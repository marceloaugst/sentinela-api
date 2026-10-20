// Package netutil reúne utilitários de rede compartilhados.
package netutil

import (
	"net"
	"net/http"
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
