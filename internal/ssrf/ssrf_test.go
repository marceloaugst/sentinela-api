package ssrf

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCheckAddrBlocksInternalRanges(t *testing.T) {
	var p Policy
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", // metadados AWS/GCP/Azure
		"169.254.0.1", "fe80::1", "fd00::1", "fc00::1",
		"100.64.0.1", // CGNAT
		"224.0.0.1", "ff02::1", "240.0.0.1", "255.255.255.255",
		"::ffff:127.0.0.1", // IPv4-mapeado
		"::ffff:169.254.169.254", "::ffff:10.1.1.1",
		"192.0.2.10", "198.18.0.1", "2001:db8::1", "64:ff9b::7f00:1",
		"fd00:ec2::254", // metadados AWS IPv6
	}
	for _, s := range blocked {
		if err := p.CheckAddr(netip.MustParseAddr(s)); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s deveria ser bloqueado", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "11.0.0.1", "2606:4700:4700::1111", "100.63.255.255"}
	for _, s := range allowed {
		if err := p.CheckAddr(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s deveria ser permitido: %v", s, err)
		}
	}
}

func TestAllowedCIDRsOverrideBlocks(t *testing.T) {
	pre, err := ParseAllowed("10.20.0.0/16, 192.168.5.5/32")
	if err != nil || len(pre) != 2 {
		t.Fatal(err)
	}
	p := Policy{Allowed: pre}
	if p.CheckAddr(netip.MustParseAddr("10.20.3.4")) != nil || p.CheckAddr(netip.MustParseAddr("192.168.5.5")) != nil {
		t.Error("CIDRs autorizados deveriam passar")
	}
	if p.CheckAddr(netip.MustParseAddr("10.21.0.1")) == nil || p.CheckAddr(netip.MustParseAddr("127.0.0.1")) == nil {
		t.Error("fora da lista autorizada continua bloqueado")
	}
	// IPv4-mapeado dentro de CIDR autorizado também é reconhecido
	if p.CheckAddr(netip.MustParseAddr("::ffff:10.20.3.4")) != nil {
		t.Error("mapeado deveria casar com o CIDR autorizado")
	}
	if _, err := ParseAllowed("10.0.0.0/99"); err == nil {
		t.Error("CIDR inválido deveria falhar")
	}
	if got, _ := ParseAllowed(" , "); len(got) != 0 {
		t.Error("lista vazia")
	}
}

func TestValidateURL(t *testing.T) {
	var p Policy
	ok := []string{"https://example.com", "http://example.com:8080/health?x=1", "https://api.exemplo.com.br/v1", "http://93.184.216.34/", "https://[2606:4700:4700::1111]/"}
	for _, u := range ok {
		if _, err := p.ValidateURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := []string{
		"", "example.com", "ftp://example.com", "file:///etc/passwd", "gopher://x.com", "javascript:alert(1)",
		"http://user:pass@example.com", "http://localhost", "http://localhost:8080/admin", "http://127.0.0.1", "http://[::1]/",
		"http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://10.0.0.5",
		"http://intranet", "http://servidor.local", "http://db.internal", "http://foo.localhost", "http://0.0.0.0",
		"http://[::ffff:127.0.0.1]/", "http://example.com:99999", "http://example.com:0", "https://", "http:///path",
		"http://2130706433/", // 127.0.0.1 em decimal: não é IP literal válido p/ netip nem tem ponto => bloqueado como interno
	}
	for _, u := range bad {
		if _, err := p.ValidateURL(u); err == nil {
			t.Errorf("%q deveria ser rejeitada", u)
		}
	}
}

func dialer(p Policy) *net.Dialer {
	return &net.Dialer{Timeout: 2 * time.Second, Control: p.Control}
}

// A defesa de verdade: mesmo que a URL passe, a conexão ao IP interno é recusada.
func TestDialerBlocksLoopbackAtConnectTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("segredo-interno")) }))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, err := dialer(Policy{}).DialContext(context.Background(), "tcp", addr)
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("conexão a loopback deveria ser bloqueada: %v", err)
	}
	// "localhost" resolve para loopback: bloqueado após a resolução DNS (cobre rebinding)
	_, port, _ := net.SplitHostPort(addr)
	if _, err := dialer(Policy{}).DialContext(context.Background(), "tcp", "localhost:"+port); err == nil {
		t.Error("localhost deveria ser bloqueado na conexão")
	}
	// com CIDR autorizado explicitamente, conecta
	allowed, _ := ParseAllowed("127.0.0.0/8")
	c, err := dialer(Policy{Allowed: allowed}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("autorizado deveria conectar: %v", err)
	}
	c.Close()
}

func TestHTTPClientWithPolicyAndNoProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1") // proxies do ambiente não podem contornar a política
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	tr := &http.Transport{DialContext: dialer(Policy{}).DialContext, Proxy: nil}
	_, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get(srv.URL)
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Errorf("esperava ErrBlocked, obteve %v", err)
	}
}
