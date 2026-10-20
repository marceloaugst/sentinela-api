package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSONEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, http.StatusCreated, map[string]string{"a": "b"}, map[string]int{"total": 1})
	if rec.Code != 201 || rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("status/header: %d %v", rec.Code, rec.Header())
	}
	var got map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["data"]["a"] != "b" || got["meta"]["total"] != float64(1) {
		t.Errorf("corpo: %s", rec.Body)
	}
}

type decodeDst struct {
	A string `json:"a"`
	N int    `json:"n"`
}

func decodeReq(body, ct string) (*httptest.ResponseRecorder, bool, decodeDst) {
	var dst decodeDst
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	req.Body = http.MaxBytesReader(rec, req.Body, 20)
	ok := Decode(rec, req, &dst)
	return rec, ok, dst
}

func TestDecode(t *testing.T) {
	rec, ok, dst := decodeReq(`{"a":"x"}`, "application/json; charset=utf-8")
	if !ok || dst.A != "x" {
		t.Fatalf("válido falhou: %d %s", rec.Code, rec.Body)
	}
	cases := []struct {
		name, body, ct string
		status         int
	}{
		{"content-type", `{}`, "text/plain", 415},
		{"json inválido", `{`, "application/json", 400},
		{"campo desconhecido", `{"z":1}`, "application/json", 400},
		{"tipo errado", `{"n":"x"}`, "application/json", 422},
		{"conteúdo extra", `{} {}`, "application/json", 400},
		{"grande demais", `{"a":"` + strings.Repeat("x", 50) + `"}`, "application/json", 413},
	}
	for _, c := range cases {
		rec, ok, _ := decodeReq(c.body, c.ct)
		if ok || rec.Code != c.status {
			t.Errorf("%s: ok=%v status=%d (esperado %d) %s", c.name, ok, rec.Code, c.status, rec.Body)
		}
	}
}

func TestJSONOmitsEmptyMeta(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, 200, "x", nil)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if _, ok := got["meta"]; ok {
		t.Error("meta deveria ser omitido")
	}
}

func TestErrorEnvelopeDetailsNeverNull(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, 422, "VALIDATION_ERROR", "Os dados informados são inválidos.")
	var got struct {
		Error struct {
			Code    string `json:"code"`
			Details []any  `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "VALIDATION_ERROR" || got.Error.Details == nil {
		t.Errorf("corpo: %s", rec.Body)
	}
}
