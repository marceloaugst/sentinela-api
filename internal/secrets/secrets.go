// Package secrets cifra segredos (ex.: token de bot) em repouso com AES-256-GCM.
// A chave vem do ambiente (SECRETS_KEY) e nunca é armazenada no banco.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

var ErrNoKey = errors.New("SECRETS_KEY não configurada")

// aad vincula o texto cifrado ao seu uso, impedindo reaproveitá-lo em outro contexto.
var aad = []byte("sentinela/notification_channels.secret/v1")

type Box struct{ aead cipher.AEAD }

// ParseKey aceita 32 bytes em hexadecimal (64 caracteres) ou base64.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("SECRETS_KEY deve ter 32 bytes em hex (64 caracteres) ou base64; gere com: openssl rand -hex 32")
}

func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("chave deve ter 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Encrypt devolve nonce || texto cifrado (nonce aleatório novo a cada chamada).
func (b *Box) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, aad), nil
}

func (b *Box) Decrypt(blob []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(blob) < n+b.aead.Overhead() {
		return nil, errors.New("segredo cifrado inválido")
	}
	plain, err := b.aead.Open(nil, blob[:n], blob[n:], aad)
	if err != nil {
		return nil, errors.New("falha ao decifrar segredo (chave incorreta ou dado corrompido)")
	}
	return plain, nil
}
