package events

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinela/internal/telemetry"
)

func newTestHub() *Hub {
	h := NewHub("", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewMetrics())
	return h
}

func ev(id int64, typ, server string) Event {
	return Event{ID: id, Type: typ, ServerID: server, Time: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), Data: json.RawMessage(`{"k":"v"}`)}
}

func TestWriteSSEFormat(t *testing.T) {
	var b bytes.Buffer
	if err := WriteSSE(&b, ev(42, TypeAlertTriggered, "")); err != nil {
		t.Fatal(err)
	}
	want := "id: 42\nevent: alert.triggered\ndata: {\"id\":42,\"type\":\"alert.triggered\",\"time\":\"2026-03-01T12:00:00Z\",\"data\":{\"k\":\"v\"}}\n\n"
	if b.String() != want {
		t.Errorf("formato:\n%q\nesperado:\n%q", b.String(), want)
	}
	// efêmero: sem id (não altera o Last-Event-ID do navegador)
	b.Reset()
	WriteSSE(&b, ev(0, TypeMetricsUpdated, ""))
	if strings.Contains(b.String(), "id:") || !strings.HasPrefix(b.String(), "event: metrics.updated\n") {
		t.Errorf("efêmero: %q", b.String())
	}
	// uma única linha de data (quebra de linha no JSON quebraria o protocolo)
	b.Reset()
	e := ev(1, TypeAlertTriggered, "")
	e.Data = json.RawMessage(`{"message":"linha1\nlinha2"}`)
	WriteSSE(&b, e)
	if n := strings.Count(b.String(), "\ndata: "); n != 1 || strings.Count(b.String(), "\n") != 4 {
		t.Errorf("data deve ficar em uma linha: %q", b.String())
	}
}

func TestFilterMatch(t *testing.T) {
	alert, metrics := ev(1, TypeAlertTriggered, "s1"), ev(0, TypeMetricsUpdated, "s1")
	// padrão: todos os tipos duráveis, mas metrics.updated é opt-in
	if f := (Filter{}); !f.Match(alert) || f.Match(metrics) {
		t.Error("padrão: duráveis sim, metrics.updated não")
	}
	f := Filter{Types: map[string]bool{TypeMetricsUpdated: true}}
	if !f.Match(metrics) || f.Match(alert) {
		t.Error("tipos explícitos")
	}
	f = Filter{ServerID: "s1"}
	if !f.Match(alert) || f.Match(ev(2, TypeAlertTriggered, "s2")) || f.Match(ev(3, TypeAlertTriggered, "")) {
		t.Error("filtro por servidor")
	}
	if !ValidType(TypeServiceStatus) || ValidType("alert.*") || ValidType("") || ValidType(TypeResync) {
		t.Error("ValidType (resync é sintético e não pode ser pedido)")
	}
}

func TestHubFanOutAndFilters(t *testing.T) {
	h := newTestHub()
	all, _ := h.Subscribe("1.1.1.1", Filter{})
	onlyS2, _ := h.Subscribe("1.1.1.2", Filter{ServerID: "s2"})
	h.Broadcast(ev(1, TypeAlertTriggered, "s1"))
	h.Broadcast(ev(2, TypeAlertTriggered, "s2"))
	if len(all.C) != 2 || len(onlyS2.C) != 1 || (<-onlyS2.C).ID != 2 {
		t.Errorf("fan-out: all=%d s2=%d", len(all.C), len(onlyS2.C))
	}
	if h.Clients() != 2 {
		t.Error("clientes")
	}
}

func TestHubLimitsTotalAndPerIP(t *testing.T) {
	h := newTestHub()
	h.MaxClients, h.MaxPerIP = 3, 2
	a, _ := h.Subscribe("1.1.1.1", Filter{})
	if _, err := h.Subscribe("1.1.1.1", Filter{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Subscribe("1.1.1.1", Filter{}); err != ErrTooManyPerIP {
		t.Errorf("limite por IP: %v", err)
	}
	if _, err := h.Subscribe("2.2.2.2", Filter{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Subscribe("3.3.3.3", Filter{}); err != ErrTooManyClients {
		t.Errorf("limite total: %v", err)
	}
	// fechar libera a vaga (contadores consistentes)
	a.Close()
	a.Close() // idempotente
	if h.Clients() != 2 {
		t.Errorf("clientes após fechar: %d", h.Clients())
	}
	if _, err := h.Subscribe("1.1.1.1", Filter{}); err != nil {
		t.Errorf("a vaga deveria ter sido liberada: %v", err)
	}
	if a.Reason() != "client" {
		t.Errorf("motivo: %s", a.Reason())
	}
}

func TestSlowClientIsDroppedWithoutBlockingOthers(t *testing.T) {
	h := newTestHub()
	h.Buffer = 3
	slow, _ := h.Subscribe("1.1.1.1", Filter{})
	fast, _ := h.Subscribe("2.2.2.2", Filter{})
	got := 0
	start := time.Now()
	for i := int64(1); i <= 10; i++ {
		h.Broadcast(ev(i, TypeAlertTriggered, ""))
		for len(fast.C) > 0 { // o cliente rápido consome a cada evento
			<-fast.C
			got++
		}
	}
	if time.Since(start) > time.Second {
		t.Fatal("Broadcast não pode bloquear por causa de cliente lento")
	}
	n := 0
	for range slow.C { // o hub fechou o canal do cliente lento
		n++
	}
	if slow.Reason() != "overflow" || n > 3 {
		t.Errorf("cliente lento: motivo=%s recebidos=%d", slow.Reason(), n)
	}
	if got != 10 || h.Clients() != 1 {
		t.Errorf("o cliente rápido deve receber tudo e permanecer: recebidos=%d clientes=%d", got, h.Clients())
	}
	fast.Close()
	if testutilCount(h) != 0 {
		t.Error("contador de clientes vazou")
	}
}

func testutilCount(h *Hub) int { return h.Clients() }

func TestHubCloseEndsAllSubscriptionsAndRejectsNew(t *testing.T) {
	h := newTestHub()
	var subs []*Sub
	for i := 0; i < 5; i++ {
		s, _ := h.Subscribe("1.1.1.1", Filter{})
		subs = append(subs, s)
	}
	h.Close()
	var wg sync.WaitGroup
	for _, s := range subs {
		wg.Add(1)
		go func(s *Sub) {
			defer wg.Done()
			for range s.C {
			}
		}(s)
	}
	wg.Wait()
	for _, s := range subs {
		if s.Reason() != "shutdown" {
			t.Errorf("motivo: %s", s.Reason())
		}
	}
	if _, err := h.Subscribe("1.1.1.1", Filter{}); err != ErrHubClosed {
		t.Errorf("novas assinaturas após Close: %v", err)
	}
	if h.Clients() != 0 {
		t.Error("clientes")
	}
}

func TestBroadcastIsRaceFree(t *testing.T) {
	h := newTestHub()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if s, err := h.Subscribe("ip", Filter{}); err == nil {
					select {
					case <-s.C:
					default:
					}
					s.Close()
				}
			}
		}()
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.Broadcast(ev(int64(i*1000+j+1), TypeAlertTriggered, ""))
			}
		}(i)
	}
	wg.Wait()
	if h.Clients() != 0 {
		t.Errorf("vazamento de assinaturas: %d", h.Clients())
	}
}

func TestBroadcastLiveParsing(t *testing.T) {
	h := newTestHub()
	s, _ := h.Subscribe("ip", Filter{Types: map[string]bool{TypeMetricsUpdated: true}})
	h.broadcastLive(`{"type":"metrics.updated","server_id":"s1","time":"2026-03-01T12:00:00Z","data":{"cpu_usage_percent":10}}`)
	h.broadcastLive(`{"type":"alert.triggered","server_id":"s1","data":{}}`) // tipo fora do filtro
	h.broadcastLive(`{"type":"tipo.inventado","data":{}}`)                   // inválido: descartado
	h.broadcastLive(`isto não é json`)
	if len(s.C) != 1 {
		t.Fatalf("esperava 1 evento: %d", len(s.C))
	}
	if e := <-s.C; e.Durable() || e.ServerID != "s1" {
		t.Errorf("efêmero sem id: %+v", e)
	}
}

func TestThrottle(t *testing.T) {
	now := time.Unix(1000, 0)
	th := NewThrottle(5 * time.Second)
	th.Now = func() time.Time { return now }
	if !th.Allow("a") || th.Allow("a") || !th.Allow("b") {
		t.Error("primeira passa, repetida não, outra chave passa")
	}
	now = now.Add(4 * time.Second)
	if th.Allow("a") {
		t.Error("ainda dentro do intervalo")
	}
	now = now.Add(2 * time.Second)
	if !th.Allow("a") {
		t.Error("após o intervalo deve passar")
	}
}
