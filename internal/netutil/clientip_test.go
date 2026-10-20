package netutil

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.9:5555"
	r.Header.Set("X-Real-IP", "203.0.113.7")

	if got := ClientIP(r, false); got != "10.0.0.9" {
		t.Errorf("sem proxy confiável deve ignorar X-Real-IP: %q", got)
	}
	if got := ClientIP(r, true); got != "203.0.113.7" {
		t.Errorf("com proxy confiável: %q", got)
	}
	r.Header.Set("X-Real-IP", "não-é-ip")
	if got := ClientIP(r, true); got != "10.0.0.9" {
		t.Errorf("X-Real-IP inválido deve cair para RemoteAddr: %q", got)
	}
}
