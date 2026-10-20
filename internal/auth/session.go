package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const sessionPrefix = "ses_"

// newToken gera um token de sessão de 256 bits. Só o hash SHA-256 vai ao banco: um vazamento do banco
// não permite sequestrar sessões (e, com 256 bits de entropia, um KDF lento seria desnecessário).
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return sessionPrefix + hex.EncodeToString(b), nil
}

func validTokenFormat(t string) bool {
	if len(t) != len(sessionPrefix)+64 || !strings.HasPrefix(t, sessionPrefix) {
		return false
	}
	for _, c := range t[len(sessionPrefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

// CSRFToken deriva o token anti-CSRF do token da sessão (HMAC-SHA256). É determinístico, então não exige
// armazenamento e pode ser reemitido em /auth/me após um reload da página; sem o cookie HttpOnly da sessão,
// um atacante não consegue calculá-lo.
func CSRFToken(sessionToken string) string {
	m := hmac.New(sha256.New, []byte(sessionToken))
	m.Write([]byte("sentinela-csrf-v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func csrfEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
