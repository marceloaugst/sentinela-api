package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestRoundTripAndRandomNonce(t *testing.T) {
	box, _ := NewBox(key(1))
	a, _ := box.Encrypt([]byte("123456:ABC-token"))
	b, _ := box.Encrypt([]byte("123456:ABC-token"))
	if bytes.Equal(a, b) {
		t.Error("nonce deve ser aleatório: mesmo texto não pode gerar o mesmo blob")
	}
	if bytes.Contains(a, []byte("ABC-token")) {
		t.Error("texto puro presente no blob cifrado")
	}
	got, err := box.Decrypt(a)
	if err != nil || string(got) != "123456:ABC-token" {
		t.Errorf("%q %v", got, err)
	}
}

func TestDecryptRejectsWrongKeyTamperingAndShort(t *testing.T) {
	box, _ := NewBox(key(1))
	other, _ := NewBox(key(2))
	blob, _ := box.Encrypt([]byte("segredo"))
	if _, err := other.Decrypt(blob); err == nil {
		t.Error("chave errada deveria falhar")
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := box.Decrypt(tampered); err == nil {
		t.Error("blob adulterado deveria falhar")
	}
	if _, err := box.Decrypt([]byte("curto")); err == nil {
		t.Error("blob curto deveria falhar")
	}
}

func TestParseKey(t *testing.T) {
	raw := key(7)
	for name, s := range map[string]string{"hex": hex.EncodeToString(raw), "base64": base64.StdEncoding.EncodeToString(raw)} {
		got, err := ParseKey(" " + s + "\n")
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "curta", strings.Repeat("a", 63), hex.EncodeToString(key(1)[:16])} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q deveria ser inválida", bad)
		}
	}
	if _, err := NewBox(key(1)[:16]); err == nil {
		t.Error("chave de 16 bytes deveria ser recusada")
	}
}
