# Frontend: processos do servidor

Guia da aba **Processos** de um servidor: lista o que mais consome CPU e memória e deixa **encerrar** os poucos processos que o agente tem permissão para encerrar. Complementa `docs/frontend-servicos-acoes.md` (o encerramento usa o mesmo acompanhamento de comandos).

## 1. Rotas

| O quê | Rota | Papel mínimo |
|---|---|---|
| Listar processos | `GET /api/v1/servers/{id}/processes?sort=&limit=&q=` | viewer |
| Encerrar um processo | `POST /api/v1/servers/{id}/processes/{pid}/actions` | operator |
| Acompanhar o comando | `GET /api/v1/service-commands/{id}` (o mesmo dos serviços) | viewer |
| Auditoria | `GET /api/v1/audit-logs?action=process.` | admin |

Parâmetros da lista: `sort` = `cpu` (padrão), `memory`, `pid` ou `name`; `limit` de 1 a 500 (padrão 100); `q` filtra por nome, linha de comando, usuário ou pid.

## 2. Resposta de `GET /servers/{id}/processes`

```json
{ "data": {
  "status": "ok",
  "message": "",
  "checked_at": "2026-10-23T10:00:00Z",
  "cpus": 4,
  "memory_total_bytes": 8318783488,
  "total": 143,
  "matched": 143,
  "processes": [
    { "pid": 4242, "start_time": 987654, "ppid": 1, "name": "node", "cmdline": "node server.js --port=3000",
      "user": "deploy", "state": "S", "threads": 11, "cpu_percent": 82.5, "memory_bytes": 412000000, "memory_percent": 5.0,
      "service_key": "", "service_name": "", "restriction": "", "restriction_message": "",
      "actions": ["terminate", "kill"] },
    { "pid": 812, "start_time": 1200, "name": "nginx", "cmdline": "nginx: master process /usr/sbin/nginx",
      "user": "root", "cpu_percent": 1.5, "memory_percent": 0.6, "service_key": "nginx", "service_name": "Nginx",
      "restriction": "service", "restriction_message": "Pertence a um serviço monitorado: use Parar ou Reiniciar na tela de serviços.",
      "actions": [] }
  ] } }
```

- `status: "unknown"` = o agente ainda não informou ("Aguardando o agente…"). Atualiza a cada ~30 s e logo depois de cada encerramento; mostre `checked_at` ("há 20 s").
- A lista traz até **300** processos: os de maior CPU e, para completar, os de maior memória. `total` é quantos existem; `matched` quantos casam com `q` antes de `limit`. Threads de kernel não aparecem.
- **`cpu_percent`**: 100 = um núcleo inteiro (como no `top`), máximo `100 × cpus`. Para exibir "% do servidor", divida por `cpus`. É a média desde a leitura anterior (~30 s), não um instante.
- **`memory_bytes`**: RSS. Páginas compartilhadas (nginx, postgres...) contam em cada processo, então a soma pode passar da RAM. `memory_percent` é sobre a RAM total.
- **`cmdline`**: texto cru, até 200 caracteres; **não interprete como HTML**. Segredos aparentes (`--password=…`, `TOKEN=…`, `usuario:senha@host`) vêm mascarados com `***`, mas é heurístico.
- `state`: `R` executando, `S` dormindo, `D` em E/S, `T` parado, `Z` zumbi.

## 3. Quem pode ser encerrado

Só o que vier com `actions: ["terminate","kill"]`. Nos demais, `actions` é `[]`: desabilite o botão e mostre `restriction_message` (tooltip).

| `restriction` | Significado | Alternativa |
|---|---|---|
| `""` | pode ser encerrado | botões abaixo |
| `other_user` | de outro usuário; o agente não é root | nenhuma por aqui |
| `service` | pertence a um serviço do catálogo (`service_key`) | Parar/Reiniciar na tela de serviços |
| `container` | processo de container Docker | Reiniciar o container na tela do Docker |
| `critical` | init, systemd, sshd, dockerd... | nenhuma |
| `self` | o próprio agente | nenhuma |

Na instalação padrão o agente roda como usuário dinâmico `sentinela-agent`, que não tem processos além dele mesmo: **na prática quase tudo aparecerá como `other_user`**. Os botões só aparecem se o agente rodar como o mesmo usuário dos processos (veja `docs/agent.md`).

## 4. Encerrar

`POST /servers/{id}/processes/{pid}/actions`

```json
{ "action": "terminate", "start_time": 987654 }
```

- `action`: `terminate` (SIGTERM, pede para sair) ou `kill` (SIGKILL, força). Sugestão de UX: o botão principal é **Encerrar** (`terminate`); se o comando voltar `failed` com "continua ativo", ofereça **Forçar** (`kill`) com confirmação.
- `start_time`: obrigatório, copie do item da lista. Garante que o alvo é o mesmo processo e não outro que reaproveitou o pid.
- Responde **202** com o comando (`service_key: "process"`, `target: "4242:987654"`, `unit` = nome do processo). Acompanhe por `GET /service-commands/{id}` até `succeeded` ou `failed`; `message` explica ("node (pid 4242) encerrado com SIGTERM.", "…recebeu SIGTERM mas continua ativo…", "O processo não existe mais.").
- Erros: `403` viewer; `404` processo/servidor inexistente (ou `start_time` que não bate); `422 ACTION_NOT_ALLOWED` processo com restrição; `409 COMMAND_IN_PROGRESS` já há pedido para ele; `422` validação.
- O pedido expira em 2 min se o agente estiver offline. Depois do resultado, recarregue a lista (o agente reenvia o retrato na hora).
- Use **confirmação** antes de enviar e mostre `name`, `pid` e `user` no diálogo.

## 5. Histórico: quem consumia no momento de um pico

`GET /api/v1/servers/{id}/processes/history?from=&to=` (viewer; exige o ClickHouse, senão `503 LOGS_UNAVAILABLE`). Padrão: última hora; máximo 7 dias; datas em RFC 3339.

```json
{ "data": { "from": "…", "to": "…", "truncated": false,
  "samples": [
    { "at": "2026-10-23T03:12:10Z", "processes": [
      { "pid": 4242, "name": "node", "user": "deploy", "cpu_percent": 97.5, "memory_bytes": 412000000 },
      { "pid": 977, "name": "postgres", "user": "postgres", "cpu_percent": 9.0, "memory_bytes": 905000000 } ] } ] } }
```

- Cada leitura (`samples[]`, da mais antiga para a mais nova) traz os 5 maiores por CPU **e** os 5 maiores por memória (união, até 10). Não há linha de comando no histórico.
- A leitura é a cada ~30 s e a cada ~10 s enquanto a CPU ou a RAM do servidor estão acima de 85 %. Um processo que viveu menos que isso pode não aparecer.
- Para investigar um alerta, use `triggered_at` e uma janela antes dele (por exemplo `from = triggered_at - 15 min`, `to = triggered_at + 1 min`) e desenhe uma linha do tempo por `name`. O gráfico fica melhor somando os `pid` de mesmo `name` em cada leitura (workers do nginx, postgres...).

## 6. Alertas que já dizem quem foi

Quando disparam, os alertas `cpu_high`, `load_high` (ordenam por CPU) e `memory_low`, `swap_high`, `oom_kill` (por memória) apontam os 3 maiores consumidores:

- O texto já vem em `message` (e na notificação e no incidente): *"Uso de CPU em 96.0% (limite: > 90%). Maiores consumidores de CPU (média dos últimos 5 min): node 85.5% de CPU, backup 7.0% de CPU."*
- O dado estruturado vem no campo **`culprits`** do alerta (`GET /alerts`, `GET /alerts/{id}`) e em cada item de `alerts[]` do incidente (`GET /incidents/{id}`); é `null` nas outras regras.

```json
"culprits": { "kind": "cpu", "source": "history", "window_seconds": 300, "at": "…",
  "processes": [ { "name": "node", "user": "deploy", "cpu_percent": 85.5, "cpu_peak": 100,
                   "memory_bytes": 412000000, "memory_peak_bytes": 450000000 } ] }
```

- `source: "history"`: média das leituras da janela em que a condição valia (a duração da regra, entre 2 e 15 min). `"snapshot"`: só a última leitura (sem ClickHouse ou sem histórico), `window_seconds` = 0. Sem nenhuma leitura recente (< 2 min), `culprits` é `null` e o alerta sai sem a lista.
- `cpu_percent`: 100 = um núcleo. Processos de mesmo nome vêm somados. Mostre também o `cpu_peak` ("pico de 100 %").
- Isso aponta o **maior consumidor**, não prova que ele causou o problema (o servidor pode estar lento por causa de disco, por exemplo).
