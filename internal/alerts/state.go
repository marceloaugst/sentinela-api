// Package alerts implementa regras, avaliação periódica, máquina de estados e deduplicação de alertas.
package alerts

import "time"

// Estados persistidos em alerts.status.
const (
	StatusPending      = "pending"      // condição verdadeira, ainda dentro de duration_seconds (não notifica)
	StatusFiring       = "firing"       // alerta ativo
	StatusAcknowledged = "acknowledged" // ativo e reconhecido por um operador
	StatusResolved     = "resolved"
)

type Action int

const (
	ActNone            Action = iota
	ActStartPending           // cria alerta pending
	ActDropPending            // condição sumiu antes de duration_seconds: descarta sem notificar
	ActFire                   // vira firing (cria ou promove pending): abre/atualiza incidente e notifica
	ActClearRecovering        // condição voltou durante a recuperação: cancela a contagem
	ActStartRecovering        // condição sumiu: inicia a contagem de recovery_seconds
	ActResolve                // recuperado: resolve alerta e incidente e notifica
)

// State é o estado persistido de um alerta para uma combinação (regra, servidor[, serviço]).
type State struct {
	Exists          bool
	Status          string
	PendingSince    *time.Time
	RecoveringSince *time.Time
}

// Decide é a função pura da máquina de estados. Recebe o estado atual, se a condição está
// verdadeira agora e os tempos da regra, e devolve a ação a aplicar. Todo o estado necessário
// vem do banco (pending_since / recovering_since), então a avaliação sobrevive a reinícios.
//
//	sem alerta ──cond──► pending ──(≥ duration)──► firing ──!cond──► recovering ──(≥ recovery)──► resolved
//	                 │       └──!cond──► descartado        ◄──cond────────┘
//	                 └──(duration = 0)──► firing
func Decide(st State, cond bool, now time.Time, durationSec, recoverySec int) Action {
	since := func(t *time.Time, secs int) bool {
		return t != nil && now.Sub(*t) >= time.Duration(secs)*time.Second
	}
	if !st.Exists {
		switch {
		case !cond:
			return ActNone
		case durationSec <= 0:
			return ActFire
		default:
			return ActStartPending
		}
	}
	if st.Status == StatusPending {
		switch {
		case !cond:
			return ActDropPending
		case since(st.PendingSince, durationSec) || st.PendingSince == nil:
			return ActFire
		default:
			return ActNone
		}
	}
	// firing ou acknowledged
	if cond {
		if st.RecoveringSince != nil {
			return ActClearRecovering
		}
		return ActNone
	}
	switch {
	case recoverySec <= 0:
		return ActResolve
	case st.RecoveringSince == nil:
		return ActStartRecovering
	case since(st.RecoveringSince, recoverySec):
		return ActResolve
	default:
		return ActNone
	}
}
