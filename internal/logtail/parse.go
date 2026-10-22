// Package logtail lê arquivos de log no agente (nginx, fail2ban, ufw), normaliza as linhas em logs.Entry
// e as entrega em lotes à API. A posição lida só avança depois que a API confirma o lote.
package logtail

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/logs"
)

// Parser converte uma linha em zero ou mais entradas. Linhas irrelevantes devolvem nil.
type Parser interface {
	Parse(line string) []logs.Entry
	// Idle é chamado após cada rodada de leitura, para descarregar agregados pendentes.
	Idle(now time.Time) []logs.Entry
}

// ---- nginx access ----

var accessRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"`)

// suspiciousPaths: fragmentos de caminho típicos de varredura/exploração.
var suspiciousPaths = []string{
	"/.env", "/.git", "/.aws", "/.ssh", "wp-login", "wp-admin", "xmlrpc.php", "phpmyadmin", "/pma",
	"/etc/passwd", "../", "%2e%2e", "cgi-bin", "eval-stdin", "/vendor/phpunit", "/actuator", "/boot.ini",
	"/shell", "/cmd", "/.DS_Store", "/server-status", "/config.json", "/admin.php", "/setup.php",
}

// NginxAccess lê o formato "combined". Em modo errorsOnly grava só 4xx/5xx e requisições suspeitas, e
// SEMPRE emite um agregado por minuto (access_summary) com o volume total.
type NginxAccess struct {
	AllRequests bool // true: grava toda requisição
	Loc         *time.Location

	cur     time.Time // minuto em agregação
	counts  [6]int    // índice = status/100 (1..5); [0] = outros
	bytes   int64
	started bool
}

func (n *NginxAccess) Parse(line string) []logs.Entry {
	m := accessRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return nil
	}
	status, _ := strconv.Atoi(m[4])
	size, _ := strconv.ParseInt(m[5], 10, 64)
	ip, ok := logs.NormalizeIP(m[1])
	if !ok {
		return nil
	}

	var out []logs.Entry
	if e, ok := n.add(ts, status, size); ok {
		out = append(out, e)
	}

	method, path := splitRequest(m[3])
	suspicious := isSuspicious(path)
	if n.AllRequests || status >= 400 || suspicious {
		sev := logs.SevInfo
		switch {
		case status >= 500:
			sev = logs.SevError
		case status >= 400 || suspicious:
			sev = logs.SevWarning
		}
		f := map[string]string{
			"method": logs.Clean(method, 16),
			"path":   logs.Clean(path, 512),
			"bytes":  strconv.FormatInt(size, 10),
			"ua":     logs.Clean(m[6], 200),
		}
		if suspicious {
			f["suspicious"] = "true"
		}
		out = append(out, logs.Entry{Time: ts, Source: logs.SourceNginx, Type: logs.TypeAccess, Severity: sev,
			IP: ip, Status: status, Fields: f, Raw: stripQueryFromRaw(line)})
	}
	return out
}

// Idle descarrega o minuto anterior quando já passou (evita atraso de até 1 min sem tráfego).
func (n *NginxAccess) Idle(now time.Time) []logs.Entry {
	if n.started && now.Truncate(time.Minute).After(n.cur) {
		return []logs.Entry{n.flush()}
	}
	return nil
}

func (n *NginxAccess) add(ts time.Time, status int, size int64) (logs.Entry, bool) {
	minute := ts.Truncate(time.Minute)
	var done logs.Entry
	flushed := false
	if n.started && minute.After(n.cur) {
		done, flushed = n.flush(), true
	}
	if !n.started {
		n.cur, n.started = minute, true
	}
	if minute.Before(n.cur) { // linha fora de ordem: conta no minuto corrente
		minute = n.cur
	}
	n.cur = minute
	idx := status / 100
	if idx < 1 || idx > 5 {
		idx = 0
	}
	n.counts[idx]++
	n.bytes += size
	return done, flushed
}

func (n *NginxAccess) flush() logs.Entry {
	total := 0
	for _, c := range n.counts {
		total += c
	}
	e := logs.Entry{Time: n.cur, Source: logs.SourceNginx, Type: logs.TypeAccessSummary, Severity: logs.SevInfo,
		Fields: map[string]string{
			"requests": strconv.Itoa(total),
			"s1xx":     strconv.Itoa(n.counts[1]), "s2xx": strconv.Itoa(n.counts[2]), "s3xx": strconv.Itoa(n.counts[3]),
			"s4xx": strconv.Itoa(n.counts[4]), "s5xx": strconv.Itoa(n.counts[5]),
			"bytes": strconv.FormatInt(n.bytes, 10),
		}}
	n.counts, n.bytes, n.started = [6]int{}, 0, false
	return e
}

func splitRequest(req string) (method, path string) {
	parts := strings.Fields(req)
	if len(parts) < 2 {
		return "-", logs.Clean(req, 512)
	}
	path = parts[1]
	if u, err := url.ParseRequestURI(path); err == nil {
		path = u.Path // descarta a query string: costuma carregar tokens
	} else if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return parts[0], path
}

// stripQueryFromRaw remove a query string do pedido na linha original.
func stripQueryFromRaw(line string) string {
	i := strings.IndexByte(line, '"')
	if i < 0 {
		return line
	}
	j := strings.IndexByte(line[i+1:], '"')
	if j < 0 {
		return line
	}
	req := line[i+1 : i+1+j]
	if q := strings.IndexByte(req, '?'); q >= 0 {
		end := strings.IndexByte(req[q:], ' ')
		if end < 0 {
			req = req[:q]
		} else {
			req = req[:q] + req[q+end:]
		}
	}
	return line[:i+1] + req + line[i+1+j:]
}

func isSuspicious(path string) bool {
	p := strings.ToLower(path)
	for _, s := range suspiciousPaths {
		if strings.Contains(p, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// ---- nginx error ----

var (
	errorRe  = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$`)
	clientRe = regexp.MustCompile(`, client: ([0-9a-fA-F:.]+)`)
	queryRe  = regexp.MustCompile(`\?[^\s"]*`)
)

type NginxError struct{ Loc *time.Location }

func (p NginxError) Idle(time.Time) []logs.Entry { return nil }

func (p NginxError) Parse(line string) []logs.Entry {
	m := errorRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	ts, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], loc(p.Loc))
	if err != nil {
		return nil
	}
	sev := logs.SevInfo
	switch m[2] {
	case "emerg", "alert", "crit":
		sev = logs.SevCritical
	case "error":
		sev = logs.SevError
	case "warn":
		sev = logs.SevWarning
	}
	msg := m[3]
	e := logs.Entry{Time: ts, Source: logs.SourceNginx, Type: logs.TypeError, Severity: sev,
		Fields: map[string]string{"level": m[2]}, Raw: queryRe.ReplaceAllString(line, "")} // query strings costumam carregar tokens
	if c := clientRe.FindStringSubmatch(msg); c != nil {
		if ip, ok := logs.NormalizeIP(c[1]); ok {
			e.IP = ip
		}
		msg = msg[:strings.Index(msg, c[0])]
	}
	e.Fields["message"] = logs.Clean(queryRe.ReplaceAllString(msg, ""), 300)
	return []logs.Entry{e}
}

// ---- fail2ban ----

var (
	f2bRe        = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3}) \S+\s+\[\d+\]: (\w+)\s+\[([^\]]+)\] (Found|Ban|Unban|Restore Ban) (\S+)`)
	f2bAlreadyRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3}) \S+\s+\[\d+\]: (\w+)\s+\[([^\]]+)\] (\S+) already banned`)
)

type Fail2ban struct{ Loc *time.Location }

func (p Fail2ban) Idle(time.Time) []logs.Entry { return nil }

func (p Fail2ban) Parse(line string) []logs.Entry {
	var date, ms, jail, ipRaw, typ string
	sev := logs.SevInfo
	if m := f2bRe.FindStringSubmatch(line); m != nil {
		date, ms, jail, ipRaw = m[1], m[2], m[4], m[6]
		switch m[5] {
		case "Found":
			typ = logs.TypeFound
		case "Ban", "Restore Ban":
			typ, sev = logs.TypeBan, logs.SevWarning
		case "Unban":
			typ = logs.TypeUnban
		}
	} else if m := f2bAlreadyRe.FindStringSubmatch(line); m != nil {
		date, ms, jail, ipRaw, typ = m[1], m[2], m[4], m[5], logs.TypeAlreadyBanned
	} else {
		return nil
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", date, loc(p.Loc))
	if err != nil {
		return nil
	}
	if n, err := strconv.Atoi(ms); err == nil {
		ts = ts.Add(time.Duration(n) * time.Millisecond)
	}
	ip, ok := logs.NormalizeIP(ipRaw)
	if !ok {
		return nil
	}
	return []logs.Entry{{Time: ts, Source: logs.SourceFail2ban, Type: typ, Severity: sev, IP: ip,
		Fields: map[string]string{"jail": logs.Clean(jail, 64)}, Raw: line}}
}

// ---- ufw ----

var (
	ufwRe       = regexp.MustCompile(`\[UFW (BLOCK|ALLOW|LIMIT BLOCK)\]`)
	syslogTime  = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) `)
	isoTimeLike = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+) `)
)

type UFW struct {
	Loc *time.Location
	Now func() time.Time // injetável em testes (ano do syslog)
}

func (p UFW) Idle(time.Time) []logs.Entry { return nil }

func (p UFW) Parse(line string) []logs.Entry {
	k := ufwRe.FindStringSubmatch(line)
	if k == nil {
		return nil
	}
	ts, ok := p.timestamp(line)
	if !ok {
		return nil
	}
	typ, sev := logs.TypeBlock, logs.SevWarning
	switch k[1] {
	case "ALLOW":
		typ, sev = logs.TypeAllow, logs.SevInfo
	case "LIMIT BLOCK":
		typ = logs.TypeLimit
	}
	kv := map[string]string{}
	for _, tok := range strings.Fields(line[strings.Index(line, k[0]):]) {
		if i := strings.IndexByte(tok, '='); i > 0 {
			kv[tok[:i]] = tok[i+1:]
		}
	}
	ip, ok := logs.NormalizeIP(kv["SRC"])
	if !ok {
		return nil
	}
	port, _ := strconv.Atoi(kv["DPT"])
	f := map[string]string{}
	set := func(name, key string) {
		if v := kv[key]; v != "" {
			f[name] = logs.Clean(v, 64)
		}
	}
	set("proto", "PROTO")
	set("dst", "DST")
	set("src_port", "SPT")
	set("in", "IN")
	set("out", "OUT")
	return []logs.Entry{{Time: ts, Source: logs.SourceFirewall, Type: typ, Severity: sev, IP: ip, Port: port,
		Fields: f, Raw: line}}
}

func (p UFW) timestamp(line string) (time.Time, bool) {
	if m := isoTimeLike.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(time.RFC3339Nano, m[1])
		return t, err == nil
	}
	m := syslogTime.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, false
	}
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	l := loc(p.Loc)
	// "Oct  2 10:11:12" -> normaliza o espaço duplo do dia com um dígito
	txt := strings.Join(strings.Fields(m[1]), " ")
	t, err := time.ParseInLocation("Jan 2 15:04:05 2006", txt+" "+strconv.Itoa(now.In(l).Year()), l)
	if err != nil {
		return time.Time{}, false
	}
	if t.After(now.Add(24 * time.Hour)) { // linha de dezembro lida em janeiro
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

func loc(l *time.Location) *time.Location {
	if l == nil {
		return time.Local
	}
	return l
}
