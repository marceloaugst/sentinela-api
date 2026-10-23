# Frontend: containers Docker

Guia da aba **Docker** de um servidor. Complementa `docs/frontend-servicos-acoes.md`. A API informa se o servidor tem Docker, lista **todos** os containers e permite **reiniciar** (ativo) ou **iniciar** (inativo). Para o inativo, mostra o **erro** e o **fim do log**.

## 1. Rotas

| O quê | Rota | Papel mínimo |
|---|---|---|
| Docker do servidor e containers | `GET /api/v1/servers/{id}/docker` | viewer |
| Iniciar ou reiniciar um container | `POST /api/v1/servers/{id}/docker/containers/{containerId}/actions` | operator |
| Acompanhar o comando | `GET /api/v1/service-commands/{id}` (o mesmo dos serviços) | viewer |
| Histórico | `GET /api/v1/servers/{id}/service-commands` (containers têm `target` preenchido) | viewer |
| Auditoria | `GET /api/v1/audit-logs?action=docker.` | admin |

## 2. Resposta de `GET /servers/{id}/docker`

```json
{ "data": {
  "status": "ok",
  "message": "",
  "checked_at": "2026-10-23T10:00:00Z",
  "summary": { "total": 3, "running": 1, "stopped": 2, "other": 0 },
  "containers": [
    { "id": "9f2c…(64 hex)", "name": "web", "image": "nginx:1.27", "state": "running",
      "status": "Up 3 hours", "exit_code": null, "oom_killed": false, "error": "", "log_tail": "",
      "started_at": null, "finished_at": null, "actions": ["restart"] },
    { "id": "ab41…", "name": "api", "image": "app:1", "state": "exited",
      "status": "Exited (1) 2 minutes ago", "exit_code": 1, "oom_killed": false,
      "error": "Saiu com erro, código 1.",
      "log_tail": "Error: cannot connect to database\n",
      "started_at": "…", "finished_at": "…", "actions": ["start"] }
  ] } }
```

### `status` (o servidor tem Docker?)

| `status` | Na tela |
|---|---|
| `ok` | lista de containers |
| `not_installed` | "Docker não encontrado neste servidor" (esconda a lista) |
| `no_access` | "Docker instalado, mas o agente não tem acesso." Mostre `message` (traz o comando para habilitar: `update.sh --docker`) |
| `unavailable` | "Docker instalado, mas parado." Mostre `message` |
| `unknown` | "Aguardando o agente…" (nenhum relatório ainda) |

Só `ok` traz `containers`. Atualiza a cada ~1 min e logo depois de cada ação.

### Por container

| `state` | Selo | Botão (`actions`) | Detalhes |
|---|---|---|---|
| `running`, `restarting` | ativo | **Reiniciar** (`restart`) | |
| `exited`, `dead` | parado | **Iniciar** (`start`) | mostre `error` e `log_tail` |
| `created` | nunca iniciado | **Iniciar** (`start`) | `error` = "Criado, mas nunca iniciado." (sem log) |
| `paused`, `removing` | em transição | nenhum (`actions: []`) | |

Para o inativo, mostre:
- **`error`**: a explicação em português ("Saiu com erro, código 1.", "Encerrado por falta de memória (OOM killer)…", "Erro do Docker: …", "Encerrado pelo sinal 9…").
- **`log_tail`**: um bloco monoespaçado, rolável, com as últimas ~15 linhas (texto cru, quebras `\n`; **não** interprete como HTML).
- `exit_code`, `oom_killed` e `finished_at` ("parou há 2 min") como apoio.

Use sempre `actions` para os botões: não deduza pelo `state`. Botões só para `operator` e `admin`.

## 3. Pedir a ação

```
POST /api/v1/servers/{id}/docker/containers/{containerId}/actions
{ "action": "restart" }        // ou "start"
```

`containerId` é o `id` completo (64 caracteres) do item. Resposta **202** com o mesmo objeto de comando dos serviços (`status: "pending"`, `target` = id do container, `unit` = nome do container, `service_name` = "Container api"). Faça polling de `GET /service-commands/{id}` a cada ~2 s até `succeeded`, `failed` ou `expired`, e recarregue `GET /servers/{id}/docker`.

| `status` | Na tela |
|---|---|
| `pending` / `running` | "Aguardando o agente…" / "Executando…" |
| `succeeded` | "Container reiniciado/iniciado" |
| `failed` | mostre `message`. Ex.: "O container api não ficou ativo: Saiu com erro, código 1." ou o erro do Docker ("port is already allocated") |
| `expired` | "Agente não respondeu" (2 min) |

Depois de iniciar/reiniciar, o agente espera ~3 s e confere se o container ficou ativo. Se caiu de novo, o comando vem `failed` com o motivo, e o `log_tail` novo aparece na próxima atualização da lista.

### Erros do POST

| HTTP / `error.code` | Quando |
|---|---|
| 403 `FORBIDDEN` | usuário é viewer |
| 404 | servidor ou container desconhecido (ou `containerId` malformado). Recarregue a lista |
| 409 `COMMAND_IN_PROGRESS` | já há comando pendente/em execução **desse container** (outros containers não são bloqueados) |
| 422 `ACTION_NOT_ALLOWED` | o estado mudou (ex.: já estava ativo). Recarregue |
| 422 `VALIDATION_ERROR` | `action` fora de `start`/`restart` (não existe parar nem remover) |

## 4. Tipos TypeScript

```ts
type DockerStatus = "ok" | "not_installed" | "no_access" | "unavailable" | "unknown";
type ContainerState = "running" | "restarting" | "exited" | "created" | "dead" | "paused" | "removing";

interface DockerContainer {
  id: string;            // 64 hex
  name: string;
  image: string;
  state: ContainerState;
  status: string;        // texto do Docker
  exit_code: number | null;
  oom_killed: boolean;
  error: string;         // vazio se ativo
  log_tail: string;      // vazio se ativo
  started_at: string | null;
  finished_at: string | null;
  actions: ("start" | "restart")[];
}

interface ServerDocker {
  status: DockerStatus;
  message: string;
  checked_at: string | null;
  summary: { total: number; running: number; stopped: number; other: number };
  containers: DockerContainer[];
}
// ServiceCommand ganhou: target: string  ("" = serviço systemd; id do container = Docker)
```

## 5. Auditoria

`GET /audit-logs?action=docker.`: `docker.start` e `docker.restart` (quem pediu: `actor`, `actor_user_id`, `ip`; `metadata.container`, `metadata.name`, `metadata.image`, `metadata.command_id`). O resultado do agente continua em `service.result` (com `metadata.container`).

## 6. Requisito no servidor (avise o admin na tela de `no_access`)

O acesso do agente ao Docker é **opcional e vem desligado**. Para habilitar: `sudo ./deploy/update.sh --docker` no servidor monitorado. Isso dá ao agente acesso ao socket do Docker, o que **equivale a root** naquele servidor (veja `docs/agent.md` e `docs/security.md`). O `log_tail` é texto cru da aplicação e pode ter dados sensíveis: ele fica visível a todos os papéis.

## 7. Checklist

1. [ ] Aba Docker lê `GET /servers/{id}/docker` e trata os cinco `status`.
2. [ ] Lista com selo de estado, imagem e `status`; resumo (`summary`).
3. [ ] Botões a partir de `actions` (só operator/admin); confirmação antes de Reiniciar.
4. [ ] Inativo: bloco com `error` + `log_tail` (texto puro, rolável).
5. [ ] POST com tratamento de 202/403/404/409/422 e polling de `/service-commands/{id}`.
6. [ ] Desabilitar os botões do container com comando `pending`/`running`.
7. [ ] Rótulos `docker.start`/`docker.restart` na Auditoria.
