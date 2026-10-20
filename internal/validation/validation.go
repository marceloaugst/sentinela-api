// Package validation define o formato de problemas de validação de entrada.
package validation

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Problem struct {
	Field   string
	Message string
}

type Problems []Problem

func (p *Problems) Add(field, msg string) { *p = append(*p, Problem{field, msg}) }

// Text valida um texto obrigatório/opcional e devolve o valor sem espaços nas pontas.
func (p *Problems) Text(field, v string, min, max int) string {
	v = strings.TrimSpace(v)
	n := utf8.RuneCountInString(v)
	switch {
	case n < min:
		if min == 1 {
			p.Add(field, "é obrigatório")
		} else {
			p.Add(field, "muito curto")
		}
	case n > max:
		p.Add(field, "excede o tamanho máximo")
	case strings.IndexFunc(v, unicode.IsControl) >= 0:
		p.Add(field, "contém caracteres de controle")
	}
	return v
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// Hostname valida nome de host ou IP (sem esquema, porta ou caminho).
func (p *Problems) Hostname(field, v string) string {
	v = p.Text(field, v, 1, 253)
	if v != "" && !hostnameRe.MatchString(v) {
		p.Add(field, "formato de hostname inválido")
	}
	return v
}
