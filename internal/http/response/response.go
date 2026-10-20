// Package response padroniza os envelopes JSON da API.
package response

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"sentinela/internal/validation"
)

type Success struct {
	Data any `json:"data"`
	Meta any `json:"meta,omitempty"`
}

type ErrorDetail struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

type ErrorBody struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Details []ErrorDetail `json:"details"`
}

type errorEnvelope struct {
	Error ErrorBody `json:"error"`
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("falha ao escrever resposta", "err", err)
	}
}

func JSON(w http.ResponseWriter, status int, data any, meta any) {
	write(w, status, Success{Data: data, Meta: meta})
}

func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

func Error(w http.ResponseWriter, status int, code, message string, details ...ErrorDetail) {
	if details == nil {
		details = []ErrorDetail{}
	}
	write(w, status, errorEnvelope{Error: ErrorBody{Code: code, Message: message, Details: details}})
}

func Internal(w http.ResponseWriter) {
	Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno do servidor.")
}

func NotFound(w http.ResponseWriter) {
	Error(w, http.StatusNotFound, "NOT_FOUND", "Recurso não encontrado.")
}

func MethodNotAllowed(w http.ResponseWriter) {
	Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Método não permitido.")
}

func BadRequest(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusBadRequest, code, message)
}

// Validation responde 422 com os problemas por campo.
func Validation(w http.ResponseWriter, problems validation.Problems) {
	details := make([]ErrorDetail, 0, len(problems))
	for _, p := range problems {
		details = append(details, ErrorDetail{Field: p.Field, Message: p.Message})
	}
	Error(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "Os dados informados são inválidos.", details...)
}

// Decode lê um único objeto JSON estrito (sem campos desconhecidos). Em caso de falha
// já escreve a resposta de erro e devolve false.
func Decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		Error(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type deve ser application/json.")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil {
		if _, e2 := dec.Token(); e2 != io.EOF {
			err = errors.New("conteúdo extra após o objeto JSON")
		}
	}
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &tooBig):
		Error(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Corpo da requisição excede o limite permitido.")
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		Error(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "Os dados informados são inválidos.",
			ErrorDetail{Field: field, Message: "tipo de valor inválido"})
	default:
		BadRequest(w, "INVALID_JSON", "Corpo da requisição não é um JSON válido.")
	}
	return false
}
