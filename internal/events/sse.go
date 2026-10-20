package events

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// WriteSSE grava um evento no formato text/event-stream. Eventos efêmeros não levam `id:` para não
// alterar o Last-Event-ID guardado pelo navegador.
func WriteSSE(w io.Writer, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if e.Durable() {
		if _, err := fmt.Fprintf(w, "id: %s\n", strconv.FormatInt(e.ID, 10)); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, body)
	return err
}
