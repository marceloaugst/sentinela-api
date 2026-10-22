package logtail

import (
	"strings"
	"testing"
	"time"

	"sentinela/internal/logs"
)

var utc = time.UTC

func TestNginxAccessFiltersAndSummarizes(t *testing.T) {
	p := &NginxAccess{Loc: utc}
	lines := []string{
		`203.0.113.9 - - [22/Oct/2026:10:11:12 +0000] "GET /index.html?token=SEGREDO HTTP/1.1" 200 512 "-" "Mozilla/5.0"`,
		`198.51.100.7 - - [22/Oct/2026:10:11:30 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8"`,
		`198.51.100.7 - - [22/Oct/2026:10:11:31 +0000] "POST /api/x HTTP/1.1" 502 0 "-" "x"`,
	}
	var out []logs.Entry
	for _, l := range lines {
		out = append(out, p.Parse(l)...)
	}
	// 200 comum não é gravado; 404 suspeito e 502 são.
	if len(out) != 2 {
		t.Fatalf("esperava 2 entradas, veio %d: %+v", len(out), out)
	}
	if out[0].Status != 404 || out[0].Severity != logs.SevWarning || out[0].Fields["suspicious"] != "true" || out[0].IP != "198.51.100.7" {
		t.Errorf("entrada 0 inesperada: %+v", out[0])
	}
	if out[1].Severity != logs.SevError {
		t.Errorf("5xx deve ser error: %+v", out[1])
	}
	// próximo minuto fecha o agregado do anterior
	next := p.Parse(`203.0.113.9 - - [22/Oct/2026:10:12:01 +0000] "GET / HTTP/1.1" 200 10 "-" "x"`)
	if len(next) != 1 || next[0].Type != logs.TypeAccessSummary {
		t.Fatalf("esperava o resumo do minuto anterior: %+v", next)
	}
	f := next[0].Fields
	if f["requests"] != "3" || f["s2xx"] != "1" || f["s4xx"] != "1" || f["s5xx"] != "1" || f["bytes"] != "665" {
		t.Errorf("resumo incorreto: %+v", f)
	}
	if !next[0].Time.Equal(time.Date(2026, 10, 22, 10, 11, 0, 0, time.UTC)) {
		t.Errorf("hora do resumo: %v", next[0].Time)
	}
}

func TestNginxAccessNeverStoresQueryString(t *testing.T) {
	p := &NginxAccess{Loc: utc, AllRequests: true}
	out := p.Parse(`203.0.113.9 - - [22/Oct/2026:10:11:12 +0000] "GET /login?token=SEGREDO&x=1 HTTP/1.1" 200 5 "-" "ua"`)
	if len(out) != 1 {
		t.Fatalf("entradas: %+v", out)
	}
	e := out[0]
	if strings.Contains(e.Raw, "SEGREDO") || strings.Contains(e.Fields["path"], "SEGREDO") {
		t.Errorf("query string vazou: %+v", e)
	}
	if e.Fields["path"] != "/login" || !strings.Contains(e.Raw, `"GET /login HTTP/1.1"`) {
		t.Errorf("path/raw inesperados: %q %q", e.Fields["path"], e.Raw)
	}
}

func TestNginxAccessIdleFlush(t *testing.T) {
	p := &NginxAccess{Loc: utc}
	p.Parse(`203.0.113.9 - - [22/Oct/2026:10:11:12 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"`)
	if got := p.Idle(time.Date(2026, 10, 22, 10, 11, 50, 0, time.UTC)); got != nil {
		t.Errorf("minuto ainda corrente: %+v", got)
	}
	got := p.Idle(time.Date(2026, 10, 22, 10, 12, 1, 0, time.UTC))
	if len(got) != 1 || got[0].Fields["requests"] != "1" {
		t.Errorf("esperava o resumo: %+v", got)
	}
	if p.Idle(time.Date(2026, 10, 22, 10, 13, 1, 0, time.UTC)) != nil {
		t.Error("não deve emitir resumo vazio")
	}
}

func TestNginxAccessGarbageIgnored(t *testing.T) {
	p := &NginxAccess{Loc: utc}
	for _, l := range []string{"", "lixo", `x - - [bad] "GET / HTTP/1.1" 200 1 "-" "-"`, `999.1.1.1 - - [22/Oct/2026:10:11:12 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`} {
		if out := p.Parse(l); out != nil {
			t.Errorf("%q deveria ser ignorada: %+v", l, out)
		}
	}
}

func TestNginxError(t *testing.T) {
	out := NginxError{Loc: utc}.Parse(`2026/10/22 10:11:12 [error] 1234#1234: *5 open() "/var/www/x" failed (2: No such file), client: 203.0.113.9, server: example.com, request: "GET /x?a=SEGREDO HTTP/1.1", host: "example.com"`)
	if len(out) != 1 {
		t.Fatalf("%+v", out)
	}
	e := out[0]
	if e.Severity != logs.SevError || e.IP != "203.0.113.9" || e.Type != logs.TypeError {
		t.Errorf("%+v", e)
	}
	if strings.Contains(e.Raw, "SEGREDO") {
		t.Errorf("query vazou no raw: %s", e.Raw)
	}
	if !strings.HasPrefix(e.Fields["message"], `open() "/var/www/x" failed`) || strings.Contains(e.Fields["message"], "client:") {
		t.Errorf("mensagem: %q", e.Fields["message"])
	}
	if got := (NginxError{Loc: utc}).Parse("2026/10/22 10:11:12 [notice] 1#1: signal process started"); len(got) != 1 || got[0].Severity != logs.SevInfo || got[0].IP != "" {
		t.Errorf("aviso sem cliente: %+v", got)
	}
}

func TestFail2ban(t *testing.T) {
	p := Fail2ban{Loc: utc}
	cases := []struct {
		line, typ, sev, ip string
	}{
		{`2026-10-22 10:11:12,345 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.9`, logs.TypeBan, logs.SevWarning, "203.0.113.9"},
		{`2026-10-22 10:11:12,345 fail2ban.actions        [812]: NOTICE  [sshd] Restore Ban 203.0.113.9`, logs.TypeBan, logs.SevWarning, "203.0.113.9"},
		{`2026-10-22 10:21:12,000 fail2ban.actions        [812]: NOTICE  [sshd] Unban 2001:db8::1`, logs.TypeUnban, logs.SevInfo, "2001:db8::1"},
		{`2026-10-22 10:11:10,100 fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.9 - 2026-10-22 10:11:10`, logs.TypeFound, logs.SevInfo, "203.0.113.9"},
		{`2026-10-22 10:11:13,100 fail2ban.actions        [812]: WARNING [sshd] 203.0.113.9 already banned`, logs.TypeAlreadyBanned, logs.SevInfo, "203.0.113.9"},
	}
	for _, c := range cases {
		out := p.Parse(c.line)
		if len(out) != 1 || out[0].Type != c.typ || out[0].Severity != c.sev || out[0].IP != c.ip || out[0].Fields["jail"] != "sshd" {
			t.Errorf("%q => %+v", c.line, out)
		}
	}
	first := p.Parse(cases[0].line)[0]
	if !first.Time.Equal(time.Date(2026, 10, 22, 10, 11, 12, 345e6, time.UTC)) {
		t.Errorf("hora com milissegundos: %v", first.Time)
	}
	if out := p.Parse(`2026-10-22 10:11:12,345 fail2ban.server         [812]: INFO    Jail 'sshd' started`); out != nil {
		t.Errorf("linha informativa deve ser ignorada: %+v", out)
	}
}

func TestUFW(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) }
	p := UFW{Loc: utc, Now: now}

	sys := `Oct  2 10:11:12 vps kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.9 DST=10.0.0.5 LEN=40 TOS=0x00 PROTO=TCP SPT=51515 DPT=22 WINDOW=1024 SYN URGP=0`
	out := p.Parse(sys)
	if len(out) != 1 {
		t.Fatalf("%+v", out)
	}
	e := out[0]
	if e.Type != logs.TypeBlock || e.IP != "203.0.113.9" || e.Port != 22 || e.Fields["proto"] != "TCP" || e.Fields["dst"] != "10.0.0.5" || e.Fields["in"] != "eth0" {
		t.Errorf("%+v", e)
	}
	if !e.Time.Equal(time.Date(2026, 10, 2, 10, 11, 12, 0, time.UTC)) {
		t.Errorf("hora syslog: %v", e.Time)
	}

	iso := `2026-10-22T10:11:12.123456+00:00 vps kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= SRC=2001:db8::9 DST=2001:db8::1 PROTO=UDP SPT=1 DPT=53`
	out = p.Parse(iso)
	if len(out) != 1 || out[0].IP != "2001:db8::9" || out[0].Port != 53 || out[0].Time.Nanosecond() != 123456000 {
		t.Errorf("iso: %+v", out)
	}

	if out := p.Parse(`Oct 22 10:11:12 vps kernel: [1.2] [UFW AUDIT] IN=eth0 SRC=1.2.3.4 DST=1.1.1.1 PROTO=TCP DPT=1`); out != nil {
		t.Errorf("AUDIT deve ser ignorado: %+v", out)
	}
	if out := p.Parse(`Oct 22 10:11:12 vps sshd[1]: Failed password`); out != nil {
		t.Errorf("linha comum: %+v", out)
	}
}

func TestUFWDecemberLineReadInJanuary(t *testing.T) {
	p := UFW{Loc: utc, Now: func() time.Time { return time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC) }}
	out := p.Parse(`Dec 31 23:59:59 vps kernel: [1.2] [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=1.1.1.1 PROTO=TCP DPT=1`)
	if len(out) != 1 || out[0].Time.Year() != 2026 {
		t.Errorf("%+v", out)
	}
}

// Entradas geradas pelos parsers precisam passar na validação da API.
func TestParsedEntriesPassAPIValidation(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var all []logs.Entry
	all = append(all, (&NginxAccess{Loc: utc, AllRequests: true}).Parse(`203.0.113.9 - - [22/Oct/2026:10:11:12 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"`)...)
	all = append(all, NginxError{Loc: utc}.Parse(`2026/10/22 10:11:12 [crit] 1#1: *1 boom, client: 203.0.113.9`)...)
	all = append(all, Fail2ban{Loc: utc}.Parse(`2026-10-22 10:11:12,345 fail2ban.actions [812]: NOTICE  [sshd] Ban 203.0.113.9`)...)
	all = append(all, UFW{Loc: utc, Now: func() time.Time { return now }}.Parse(`Oct 22 10:11:12 vps kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=1.1.1.1 PROTO=TCP DPT=1`)...)
	if len(all) != 4 {
		t.Fatalf("entradas: %d", len(all))
	}
	b := logs.Batch{BatchID: "abcdef123456", Entries: all}
	if p := b.Validate(now); len(p) > 0 {
		t.Errorf("validação: %+v", p)
	}
}
