package procs

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Mascaramento de segredos aparentes na linha de comando dos processos. A linha de comando é visível a qualquer
// usuário com papel viewer, então o agente mascara antes de enviar e a API mascara de novo ao receber (cobre
// agentes antigos). É heurístico: reduz o vazamento, não o garante.

const mask = "***"

var (
	secretKeyRe  = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|secret|token|api[-_]?key|apikey|auth|credential|private[-_]?key|cookie)`)
	queryKeyRe   = regexp.MustCompile(`(?i)(^key$|^sig$|signature)`)
	userinfoRe   = regexp.MustCompile(`(://[^/\s:@]+:)[^/\s@]+@`)
	flagOrAssign = regexp.MustCompile(`^(-{0,2}[A-Za-z0-9_.-]+)=(.*)$`)
	headerRe     = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$`)
	queryParamRe = regexp.MustCompile(`([?&;])([^=&;#\s]+)=([^&;#\s]*)`)
	// Esquemas de autenticação HTTP: "Bearer x" vira "Bearer ***".
	authSchemes = map[string]bool{"bearer": true, "basic": true, "digest": true, "token": true, "negotiate": true}
)

// progRule descreve opções curtas de programas conhecidos que carregam segredo sem um nome que o denuncie.
type progRule struct {
	attached string   // valor colado: mysql -pSENHA
	separate string   // valor no argumento seguinte: redis-cli -a SENHA
	userPass []string // valor "usuário:senha" (ou "usuário%senha"): curl -u, smbclient -U
}

var programRules = func() map[string]progRule {
	m := map[string]progRule{}
	for _, p := range []string{"mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlshow", "mysqlcheck", "mysqlpump",
		"mysqlbinlog", "mysqlsh", "mariadb", "mariadb-dump", "mariadb-admin", "mariadb-import", "mariadb-check", "mariadb-show"} {
		m[p] = progRule{attached: "-p"}
	}
	for _, p := range []string{"redis-cli", "valkey-cli", "keydb-cli"} {
		m[p] = progRule{separate: "-a"}
	}
	for _, p := range []string{"mongo", "mongosh", "mongodump", "mongorestore", "mongoexport", "mongoimport", "mongostat", "mongotop"} {
		m[p] = progRule{separate: "-p"}
	}
	m["sshpass"] = progRule{attached: "-p", separate: "-p"}
	m["curl"] = progRule{userPass: []string{"-u", "--user", "-U", "--proxy-user"}}
	m["smbclient"] = progRule{userPass: []string{"-U", "--user"}}
	return m
}()

// O que fazer com o argumento seguinte.
type nextArg int

const (
	nextKeep     nextArg = iota
	nextMask             // segredo inteiro: --password SENHA
	nextHeader           // valor de cabeçalho sensível já separado por espaços: "Authorization:" "Bearer" "x"
	nextUserPass         // usuário:senha
)

// redactCmdline junta os argumentos (separados por NUL, como em /proc/<pid>/cmdline) mascarando segredos aparentes.
func redactCmdline(b []byte) string {
	return strings.Join(redactArgs(strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")), " ")
}

// RedactCmdline mascara uma linha de comando já unida por espaços (a que o agente envia). Usada pela API.
func RedactCmdline(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return cmd
	}
	if r := strings.Join(redactArgs(f), " "); r != strings.Join(f, " ") {
		return r
	}
	return cmd
}

func redactArgs(args []string) []string {
	out := make([]string, len(args))
	var rule *progRule
	next := nextKeep
	for i, a := range args {
		switch next {
		case nextMask:
			out[i], next = mask, nextKeep
			continue
		case nextHeader:
			if authSchemes[strings.ToLower(a)] {
				out[i], next = a, nextMask
			} else {
				out[i], next = mask, nextKeep
			}
			continue
		case nextUserPass:
			out[i], next = maskUserPass(a), nextKeep
			continue
		}
		// O programa em uso muda quando aparece um conhecido (cobre sudo, env, docker exec etc.).
		if !strings.HasPrefix(a, "-") {
			if r, ok := programRules[filepath.Base(a)]; ok {
				rule = &r
			}
		}
		out[i], next = redactArg(a, rule)
	}
	return out
}

func redactArg(a string, rule *progRule) (string, nextArg) {
	if rule != nil && strings.HasPrefix(a, "-") {
		for _, f := range rule.userPass {
			switch {
			case a == f:
				return a, nextUserPass
			case strings.HasPrefix(a, f+"="):
				return f + "=" + maskUserPass(a[len(f)+1:]), nextKeep
			case len(f) == 2 && strings.HasPrefix(a, f):
				return f + maskUserPass(a[2:]), nextKeep
			}
		}
		if rule.separate != "" && a == rule.separate {
			return a, nextMask
		}
		if rule.attached != "" && strings.HasPrefix(a, rule.attached) && len(a) > len(rule.attached) {
			return rule.attached + mask, nextKeep
		}
	}
	if m := flagOrAssign.FindStringSubmatch(a); m != nil {
		if secretKeyRe.MatchString(m[1]) {
			return m[1] + "=" + mask, nextKeep
		}
		return m[1] + "=" + redactValue(m[2]), nextKeep // ex.: --header=Authorization: Bearer x
	}
	if strings.HasPrefix(a, "-") && !strings.Contains(a, "=") && secretKeyRe.MatchString(a) {
		return a, nextMask
	}
	if m := headerRe.FindStringSubmatch(a); m != nil && m[2] == "" && secretKeyRe.MatchString(m[1]) {
		return a, nextHeader // "Authorization:" com o valor nos argumentos seguintes
	}
	if strings.EqualFold(a, "bearer") || strings.EqualFold(a, "basic") {
		return a, nextMask
	}
	return redactValue(a), nextKeep
}

// redactValue trata um valor livre: cabeçalho sensível, argumento com espaços (bash -c "..."), URL.
func redactValue(a string) string {
	if m := headerRe.FindStringSubmatch(a); m != nil && m[2] != "" && secretKeyRe.MatchString(m[1]) {
		return m[1] + ": " + maskHeaderValue(m[2])
	}
	if strings.ContainsAny(a, " \t") {
		f := strings.Fields(a)
		if r := strings.Join(redactArgs(f), " "); r != strings.Join(f, " ") {
			return r
		}
	}
	return redactURL(a)
}

func redactURL(a string) string {
	a = userinfoRe.ReplaceAllString(a, "${1}"+mask+"@")
	return queryParamRe.ReplaceAllStringFunc(a, func(s string) string {
		m := queryParamRe.FindStringSubmatch(s)
		if m[3] != "" && (secretKeyRe.MatchString(m[2]) || queryKeyRe.MatchString(m[2])) {
			return m[1] + m[2] + "=" + mask
		}
		return s
	})
}

func maskHeaderValue(v string) string {
	if scheme, _, ok := strings.Cut(strings.TrimSpace(v), " "); ok && authSchemes[strings.ToLower(scheme)] {
		return scheme + " " + mask
	}
	return mask
}

// maskUserPass mantém o usuário e mascara a senha em "usuário:senha" ou "usuário%senha"; sem senha, nada muda.
func maskUserPass(v string) string {
	if i := strings.IndexAny(v, ":%"); i >= 0 && i < len(v)-1 {
		return v[:i+1] + mask
	}
	return v
}
