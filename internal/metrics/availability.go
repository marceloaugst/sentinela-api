package metrics

import "time"

// Availability devolve o percentual (0–100) de [from, to) em que o servidor esteve
// "online". Cada amostra recebida em t mantém o servidor online por até `timeout`
// (ou até a amostra seguinte, o que vier primeiro). Lacunas maiores que o timeout
// contam como indisponibilidade. `times` deve estar em ordem crescente e pode incluir
// amostras anteriores a `from` (elas ainda podem cobrir o início da janela).
func Availability(times []time.Time, from, to time.Time, timeout time.Duration) float64 {
	if !to.After(from) || timeout <= 0 {
		return 0
	}
	var covered time.Duration
	for i, t := range times {
		end := t.Add(timeout)
		if i+1 < len(times) && times[i+1].Before(end) {
			end = times[i+1]
		}
		start := t
		if start.Before(from) {
			start = from
		}
		if end.After(to) {
			end = to
		}
		if end.After(start) {
			covered += end.Sub(start)
		}
	}
	return float64(covered) / float64(to.Sub(from)) * 100
}
