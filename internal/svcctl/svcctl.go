// Package svcctl executa, no agente, os comandos de serviço pedidos pela API (iniciar, parar, reiniciar).
// A API manda só (chave do catálogo, ação). A unidade vem da PRÓPRIA descoberta do agente e precisa casar
// com a lista fixa do catálogo; o programa é sempre `systemctl`, sem shell. O agente continua sem
// privilégios: quem autoriza é a regra polkit (deploy/50-sentinela-agent.rules), limitada às mesmas unidades.
package svcctl

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"sentinela/internal/collector"
	"sentinela/internal/discovery"
	"sentinela/internal/dockerhost"
	"sentinela/internal/procs"
	"sentinela/internal/svcactions"
)

const execTimeout = 60 * time.Second

// Runner executa um programa e devolve a saída combinada. Injetável em testes.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

type Executor struct {
	Discoverer *collector.Discoverer
	Run        Runner
	Docker     *dockerhost.Client
	// Procs é o leitor de /proc compartilhado com a coleta (encerrar processo confere com as mesmas regras da listagem).
	Procs *procs.Scanner
	// Settle é a espera, depois de iniciar/reiniciar um container, antes de conferir se ele ficou ativo.
	Settle time.Duration
}

func New(sc *procs.Scanner) *Executor {
	return &Executor{Procs: sc, Discoverer: collector.NewDiscoverer(), Run: runCmd, Docker: dockerhost.NewClient(os.Getenv("SENTINELA_DOCKER_SOCKET")), Settle: 3 * time.Second}
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

// Execute roda o comando e devolve (status, mensagem) no vocabulário da API.
func (e *Executor) Execute(ctx context.Context, key, action string) (string, string) {
	if !svcactions.ValidAction(action) {
		return svcactions.StatusFailed, "ação desconhecida"
	}
	var found *discovery.Finding
	for _, f := range e.Discoverer.Discover() {
		if f.Key == key {
			f := f
			found = &f
			break
		}
	}
	if found == nil {
		return svcactions.StatusFailed, "serviço fora do catálogo"
	}
	// O agente confere por conta própria o que a API já conferiu.
	if !svcactions.Contains(svcactions.Allowed(key, found.Status, found.Source, found.Unit), action) {
		return svcactions.StatusFailed, "ação não permitida para o estado atual do serviço neste servidor"
	}
	unit, ok := TargetUnit(key, found.Unit)
	if !ok {
		return svcactions.StatusFailed, "unidade systemd não reconhecida"
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	out, err := e.Run(ctx, "systemctl", "--no-ask-password", action, unit)
	if err != nil {
		msg := lastLine(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return svcactions.StatusFailed, msg
	}
	return svcactions.StatusSucceeded, "systemctl " + action + " " + unit
}

// TargetUnit escolhe a unidade a controlar: a descoberta pode apontar o .socket (ssh.socket, docker.socket),
// mas o comando vai para o .service correspondente. Recusa o que não casar com o catálogo da chave.
func TargetUnit(key, unit string) (string, bool) {
	if base, ok := strings.CutSuffix(unit, ".socket"); ok {
		unit = base + ".service"
	}
	if strings.Contains(unit, "@.") || strings.ContainsAny(unit, "*/ ") {
		return "", false
	}
	spec, ok := discovery.Lookup(key)
	if !ok {
		return "", false
	}
	for _, p := range spec.Units {
		if prefix, glob := strings.CutSuffix(p, "*"); glob {
			if strings.HasPrefix(unit, prefix) && strings.HasSuffix(unit, ".service") {
				return unit, true
			}
		} else if p == unit && strings.HasSuffix(unit, ".service") {
			return unit, true
		}
	}
	return "", false
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// ExecuteContainer inicia ou reinicia um container Docker. O id e a ação são conferidos contra a listagem do
// próprio agente (ativo só reinicia, inativo só inicia). Se o container não ficar ativo logo depois, o resultado
// é falha com o motivo (código de saída, erro do Docker), para a tela mostrar o que aconteceu.
func (e *Executor) ExecuteContainer(ctx context.Context, id, action string) (string, string) {
	if !dockerhost.ValidID(id) || !dockerhost.ValidAction(action) {
		return svcactions.StatusFailed, "container ou ação inválidos"
	}
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	if status, msg := e.Docker.Detect(ctx); status != dockerhost.StatusOK {
		return svcactions.StatusFailed, msg
	}
	list, err := e.Docker.List(ctx)
	if err != nil {
		return svcactions.StatusFailed, "Falha ao listar containers: " + err.Error()
	}
	var found *dockerhost.Container
	for i := range list {
		if list[i].ID == id {
			found = &list[i]
		}
	}
	if found == nil {
		return svcactions.StatusFailed, "container não encontrado neste servidor"
	}
	if !dockerhost.Contains(dockerhost.Allowed(found.State), action) {
		return svcactions.StatusFailed, "ação não permitida para o estado atual do container (" + found.State + ")"
	}
	if action == dockerhost.ActionRestart {
		err = e.Docker.Restart(ctx, id)
	} else {
		err = e.Docker.Start(ctx, id)
	}
	if err != nil {
		return svcactions.StatusFailed, err.Error()
	}
	select {
	case <-time.After(e.Settle):
	case <-ctx.Done():
	}
	running, why, err := e.Docker.Settled(ctx, id)
	switch {
	case err != nil:
		return svcactions.StatusFailed, "Comando enviado, mas não foi possível conferir o resultado: " + err.Error()
	case !running:
		return svcactions.StatusFailed, "O container " + found.Name + " não ficou ativo: " + why
	}
	return svcactions.StatusSucceeded, "docker " + action + " " + found.Name
}

// ExecuteProcess encerra um processo ("<pid>:<início>") com SIGTERM (terminate) ou SIGKILL (kill). Quem confere se pode
// é procs.Scanner.Terminate: mesmo usuário do agente, fora de serviços, containers e processos do sistema.
func (e *Executor) ExecuteProcess(ctx context.Context, target, action string) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	ok, msg := e.Procs.Terminate(ctx, target, action)
	if !ok {
		return svcactions.StatusFailed, msg
	}
	return svcactions.StatusSucceeded, msg
}
