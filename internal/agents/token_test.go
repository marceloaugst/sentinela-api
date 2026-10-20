package agents

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateTokenUniqueAndHashed(t *testing.T) {
	t1, h1, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, _, _ := GenerateToken()
	if t1 == t2 {
		t.Error("tokens repetidos")
	}
	if !strings.HasPrefix(t1, TokenPrefix) || len(t1) != tokenLen {
		t.Errorf("formato: %q", t1)
	}
	if !bytes.Equal(h1, HashToken(t1)) || len(h1) != 32 {
		t.Error("hash inconsistente")
	}
	if bytes.Contains(h1, []byte(t1)) {
		t.Error("hash não deve conter o token")
	}
}

func TestParseBearer(t *testing.T) {
	tok, _, _ := GenerateToken()
	if got, ok := ParseBearer("Bearer " + tok); !ok || got != tok {
		t.Error("token válido rejeitado")
	}
	if _, ok := ParseBearer("bearer " + tok); !ok {
		t.Error("esquema deve ser case-insensitive")
	}
	bad := []string{"", tok, "Basic " + tok, "Bearer ", "Bearer snt_xyz", "Bearer " + strings.ToUpper(tok),
		"Bearer " + tok + "00", "Bearer abc_" + tok[len(TokenPrefix):]}
	for _, h := range bad {
		if _, ok := ParseBearer(h); ok {
			t.Errorf("deveria rejeitar %q", h)
		}
	}
}
