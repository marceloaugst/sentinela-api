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

func TestLimitKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":                   "203.0.113.7",
		"::ffff:203.0.113.7":            "203.0.113.7", // IPv4 mapeado conta como o IPv4
		"2001:db8:1:2:3:4:5:6":          "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:ffff:1": "2001:db8:1:2::/64", // mesmo /64: mesma chave
		"2001:db8::1":                   "2001:db8::/64",
		"2001:db8:0:1::1":               "2001:db8:0:1::/64", // outro /64: outra chave
		"fe80::1%eth0":                  "fe80::/64",
		"::1":                           "::/64",
		"não-é-ip":                      "não-é-ip",
	}
	for in, want := range cases {
		if got := LimitKey(in); got != want {
			t.Errorf("LimitKey(%q) = %q; esperado %q", in, got, want)
		}
	}
	if got := Network("203.0.113.7").String(); got != "203.0.113.7/32" {
		t.Errorf("Network IPv4 = %q", got)
	}
	if Network("lixo").IsValid() {
		t.Error("Network de texto inválido deveria ser inválida")
	}
}
