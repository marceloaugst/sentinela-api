# Frontend: iniciar, parar e reiniciar serviços

Guia do que mudou na aba **Serviços** de um servidor. Complementa `docs/frontend-servicos-automaticos.md`.

## 1. O que é novo

| O quê | Rota | Papel mínimo |
|---|---|---|
| Pedir ação em um serviço | `POST /api/v1/servers/{id}/services/{key}/actions` | operator |
| Acompanhar um comando | `GET /api/v1/service-commands/{id}` | viewer |
| Histórico de comandos do servidor | `GET /api/v1/servers/{id}/service-commands?limit=20` (máx. 100) | viewer |
| Campo novo `actions` em cada item | `GET /api/v1/servers/{id}/discovery` | viewer |
| Novas ações na Auditoria | `GET /api/v1/audit-logs?action=service.` | admin |

`{key}` é a chave do catálogo: `ssh`, `cron`, `timesyncd`, `rsyslog`, `nginx`, `redis`, `docker`, `postgresql` (a mesma `key` do item da descoberta).

## 2. Como montar os botões

Use o campo **`actions`** de cada item da descoberta. Ele já diz o que o usuário pode pedir **agora**.

```json
{ "key": "nginx", "name": "Nginx", "available": true, "status": "available",
  "source": "systemd", "unit": "nginx.service", "action": "",
  "actions": ["stop", "restart"], "checked_at": "…", "status_changed_at": "…" }
```

| Situação do serviço | `actions` | Botões |
|---|---|---|
| Em execução via systemd | `["stop","restart"]` | Parar, Reiniciar |
| Instalado e parado | `["start"]` | Iniciar |
| SSH em execução | `["restart"]` | Reiniciar (sem Parar) |
| Qualquer caso desativado (seção 4) | `[]` | nenhum botão |

Regras de tela:
- Mostre os botões **só para `operator` e `admin`** (`GET /auth/me` traz o papel). Para `viewer`, esconda.
- Peça **confirmação** antes de Parar e Reiniciar. Avise: parar um serviço dispara o alerta "Serviço indisponível" em ~2 min.
- Não use o texto `action` (singular, o "o que fazer" com `apt install…`) como botão. Continua só informativo.

## 3. Fluxo de um comando

```
POST /api/v1/servers/{id}/services/nginx/actions
{ "action": "restart" }
```

Resposta **202**:

```json
{ "data": { "id": "uuid", "server_id": "uuid", "service_key": "nginx", "service_name": "Nginx",
            "unit": "nginx.service", "action": "restart", "status": "pending",
            "requested_by": "uuid-do-usuario", "requested_actor": "ana@empresa.com",
            "message": "", "created_at": "…", "started_at": null, "finished_at": null } }
```

A execução é **assíncrona** (o agente busca o comando em até ~5 s):

1. Guarde o `id` e faça polling em `GET /service-commands/{id}` a cada ~2 s.
2. Pare quando `status` for `succeeded`, `failed` ou `expired`.
3. Recarregue `GET /servers/{id}/discovery`. O agente já reenviou o novo estado.

| `status` | Significado | Na tela |
|---|---|---|
| `pending` | esperando o agente buscar | "Aguardando o agente…" |
| `running` | agente executando | "Executando…" |
| `succeeded` | concluído | "Reiniciado com sucesso" |
| `failed` | erro. Veja `message` (texto do `systemctl`) | mostre `message` |
| `expired` | agente não buscou em 2 min (offline?) | "Agente não respondeu" |

Um comando em `running` sem resultado em 5 min vira `failed`.

### Erros do POST

| HTTP / `error.code` | Quando | O que fazer |
|---|---|---|
| 403 `FORBIDDEN` | usuário é viewer | esconder botões |
| 404 | servidor ou serviço inexistente, ou nunca descoberto | recarregar a tela |
| 409 `COMMAND_IN_PROGRESS` | já há comando pendente ou em execução desse serviço | desabilitar os botões enquanto houver |
| 422 `ACTION_NOT_ALLOWED` | o estado mudou (ex.: já estava parado) | recarregar a descoberta |
| 422 `VALIDATION_ERROR` | `action` fora de `start`, `stop`, `restart` | bug do front |

Dica: ao abrir a aba, olhe `GET /servers/{id}/service-commands?limit=10`. Se houver comando `pending` ou `running`, mostre o spinner e desabilite os botões desse serviço.

## 4. O que está desativado (sem botões)

| Caso | Por quê |
|---|---|
| **Parar o SSH** (só Iniciar/Reiniciar) | pararia o acesso do administrador ao servidor |
| **`journald`** (nenhuma ação) | derrubá-lo perde logs do sistema |
| **`ufw`** (nenhuma ação) | não é um daemon. Ligar/desligar muda regras de firewall e pode bloquear o SSH |
| **Redis/PostgreSQL em container Docker** (`source: "docker"`) | não são unidades systemd. Containers têm tela própria: veja `docs/frontend-docker.md` |
| **Processo solto** (`source: "process"`, fora do systemd) | não há unidade para controlar |
| **Serviço `not_found`** (não instalado) | não há o que iniciar. Continua o texto `action` com a instalação |
| **Iniciar** serviço que já roda, ou **Parar/Reiniciar** serviço parado | não faz sentido. A API devolve 422 |
| **`viewer`** | só leitura (403) |
| **Servidor com agente offline** | o botão funciona, mas o comando expira (`expired`) em 2 min |
| **Outras ações** (`enable`, `disable`, `mask`, `kill`) | não existem. A regra polkit nega |

Já estava removido antes (`docs/frontend-servicos-automaticos.md`): cadastrar, editar e excluir serviço, e o "Verificar agora". `GET /services` e `GET /services/{id}` são somente leitura.

## 5. Auditoria (tela do admin)

`GET /audit-logs?action=service.` (o ponto final filtra por prefixo) traz:

| `action` | Quando | Campos úteis |
|---|---|---|
| `service.start`, `service.stop`, `service.restart` | alguém pediu | `actor` (e-mail ou `api_key`), `actor_user_id`, `ip`, `resource_type: "server"`, `resource_id` (id do servidor), `metadata.service`, `metadata.unit`, `metadata.command_id` |
| `service.result` | o agente respondeu | `actor: "agente"`, `metadata.result` (`succeeded` ou `failed`), `metadata.message`, `metadata.command_id` |

Sugestão de rótulos: `service.start` → "Iniciou serviço", `service.stop` → "Parou serviço", `service.restart` → "Reiniciou serviço", `service.result` → "Resultado do agente".

## 6. Tipos TypeScript

```ts
type ServiceAction = "start" | "stop" | "restart";
type CommandStatus = "pending" | "running" | "succeeded" | "failed" | "expired";

interface DiscoveryItem {
  // …campos anteriores
  actions: ServiceAction[]; // novo; [] = sem botões
}

interface ServiceCommand {
  id: string;
  server_id: string;
  service_key: string;
  service_name: string;
  unit: string;
  action: ServiceAction;
  status: CommandStatus;
  requested_by: string | null;   // null se a conta foi removida ou foi a chave de API
  requested_actor: string;       // e-mail ou "api_key"
  message: string;               // vazio até terminar
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}
```

## 7. Checklist

1. [ ] Ler `actions` em `GET /servers/{id}/discovery` e renderizar os botões (só operator/admin).
2. [ ] Diálogo de confirmação para Parar e Reiniciar.
3. [ ] `POST …/actions` e tratar 202, 403, 404, 409 e 422.
4. [ ] Polling de `GET /service-commands/{id}` até `succeeded`, `failed` ou `expired`, e recarregar a descoberta no fim.
5. [ ] Desabilitar os botões do serviço enquanto houver comando `pending` ou `running`.
6. [ ] Histórico por servidor com `requested_actor` e `message`.
7. [ ] Rótulos das ações `service.*` na tela de Auditoria.

## 8. Requisito no servidor monitorado

Os botões só funcionam depois de rodar `deploy/update.sh` (ou reinstalar o agente). Ele instala a regra polkit `/etc/polkit-1/rules.d/50-sentinela-agent.rules`. Sem ela, o comando termina como `failed` com `Access denied`.
