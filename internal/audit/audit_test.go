package audit

import "testing"

func TestRedact(t *testing.T) {
	in := map[string]any{"name": "web-1", "token": "snt_abc", "Password": "x", "token_hash": "h", "api_key": "k", "status": "active"}
	out := Redact(in)
	for _, k := range []string{"token", "Password", "token_hash", "api_key"} {
		if out[k] != "[redacted]" {
			t.Errorf("%s não foi ocultado: %v", k, out[k])
		}
	}
	if out["name"] != "web-1" || out["status"] != "active" {
		t.Errorf("campos normais alterados: %v", out)
	}
	if in["token"] != "snt_abc" {
		t.Error("não deve mutar a entrada")
	}
}
