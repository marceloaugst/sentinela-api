package metrics

import "time"

// MaxSampleGap: acima disso o intervalo entre amostras é considerado uma lacuna
// (agente parado/offline) e a taxa média não é representativa.
const MaxSampleGap = 10 * time.Minute

// NetSample é uma leitura dos contadores ACUMULADOS de rede.
type NetSample struct {
	At time.Time
	RX int64
	TX int64
}

type Rate struct {
	At            time.Time `json:"at"`
	RXBytesPerSec float64   `json:"rx_bytes_per_sec"`
	TXBytesPerSec float64   `json:"tx_bytes_per_sec"`
}

// CalcRate calcula a taxa entre duas amostras consecutivas. Devolve ok=false quando
// o par não é confiável: tempo não crescente, lacuna grande demais ou contador que
// diminuiu (reinício da máquina/interface ou troca de interfaces).
func CalcRate(prev, cur NetSample) (Rate, bool) {
	dt := cur.At.Sub(prev.At)
	if dt <= 0 || dt > MaxSampleGap {
		return Rate{}, false
	}
	if cur.RX < prev.RX || cur.TX < prev.TX {
		return Rate{}, false
	}
	secs := dt.Seconds()
	return Rate{
		At:            cur.At,
		RXBytesPerSec: float64(cur.RX-prev.RX) / secs,
		TXBytesPerSec: float64(cur.TX-prev.TX) / secs,
	}, true
}

// Rates converte uma série ordenada por tempo em taxas, pulando pares inválidos
// (o ponto seguinte a um reset volta a ter taxa válida).
func Rates(samples []NetSample) []Rate {
	out := make([]Rate, 0, len(samples))
	for i := 1; i < len(samples); i++ {
		if r, ok := CalcRate(samples[i-1], samples[i]); ok {
			out = append(out, r)
		}
	}
	return out
}
