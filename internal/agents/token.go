// Package agents cuida das credenciais e da autenticação dos agentes.
package agents

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	TokenPrefix = "snt_"
	tokenBytes  = 32
	tokenLen    = len(TokenPrefix) + tokenBytes*2
)

// GenerateToken cria um token de 256 bits. Só o hash deve ser persistido.
func GenerateToken() (token string, hash []byte, err error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = TokenPrefix + hex.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken usa SHA-256: o token tem 256 bits de entropia, então um KDF lento é desnecessário.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ParseBearer extrai e valida o formato do token do cabeçalho Authorization.
func ParseBearer(header string) (string, bool) {
	scheme, tok, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	if len(tok) != tokenLen || !strings.HasPrefix(tok, TokenPrefix) {
		return "", false
	}
	for _, c := range tok[len(TokenPrefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return tok, true
}
