# Logs (nginx, fail2ban, firewall)

O agente lê os logs do servidor, normaliza cada linha e envia à API, que grava no **ClickHouse**. O PostgreSQL continua guardando só o estado (servidores, alertas, usuários...). Os arquivos originais em `/var/log` não são alterados.

```
/var/log/nginx/*.log ─┐
/var/log/fail2ban.log ├─ agente (tail + parsers) ── POST /api/v1/agent/logs ──► API ──► ClickHouse (tabela logs, TTL)
/var/log/ufw.log ─────┘                                                          └─► evento SSE security.ip_banned
```

## Ativação
1. **API:** o `deploy/compose.yaml` já sobe o ClickHouse e configura `CLICKHOUSE_URL`. Defina `CLICKHOUSE_PASSWORD` no `.env` (o `setup-server.sh` gera). Sem `CLICKHOUSE_URL` o recurso fica desativado e `/api/v1/logs*` responde `503 LOGS_UNAVAILABLE`.
2. **Agente:** defina `SENTINELA_LOGS=nginx,fail2ban,ufw` (qualquer subconjunto). No `deploy/sentinela-agent.service` basta tirar o comentário da linha `Environment=SENTINELA_LOGS=...`; o `deploy/setup-local-agent.sh` detecta sozinho quais logs existem. O unit já inclui `SupplementaryGroups=adm` (leitura de `/var/log/nginx`, `fail2ban.log` e `ufw.log` em Debian/Ubuntu) e `StateDirectory=sentinela`.

| Variável (agente) | Padrão | |
|---|---|---|
| `SENTINELA_LOGS` | vazio (desativado) | `nginx`, `fail2ban`, `ufw` separados por vírgula |
| `SENTINELA_LOG_NGINX_ACCESS_PATH` / `_ERROR_PATH` | `/var/log/nginx/access.log` / `error.log` | caminhos absolutos |
| `SENTINELA_LOG_FAIL2BAN_PATH` | `/var/log/fail2ban.log` | |
| `SENTINELA_LOG_UFW_PATH` | `/var/log/ufw.log` | se o ufw loga em `kern.log`/`syslog`, aponte para lá (só linhas `[UFW ...]` são lidas) |
| `SENTINELA_LOG_NGINX_ALL` | `false` | `true` grava todo pedido do access log |
| `SENTINELA_LOG_FROM_START` | `false` | `true` lê o arquivo inteiro na primeira execução (padrão: só linhas novas) |
| `SENTINELA_STATE_DIR` | `$STATE_DIRECTORY` | onde fica `logtail.json` (posição de leitura) |

| Variável (API) | Padrão | |
|---|---|---|
| `CLICKHOUSE_URL` | vazio (desativado) | `http://clickhouse:8123` |
| `CLICKHOUSE_DB` / `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` | `sentinela` / — / — | |
| `LOGS_RETENTION_DAYS` | `90` | vira o TTL da tabela; o ClickHouse apaga sozinho |

## O que é gravado
| Fonte | `type` | Observações |
|---|---|---|
| nginx | `access` | só **4xx/5xx** e requisições **suspeitas** (`/.env`, `wp-login`, `../`, `phpmyadmin`...), a menos que `SENTINELA_LOG_NGINX_ALL=true`. `fields`: `method`, `path`, `bytes`, `ua`, `suspicious` |
| nginx | `access_summary` | **um por minuto** com o volume total (`requests`, `s2xx`...`s5xx`, `bytes`), mesmo sem gravar cada pedido |
| nginx | `error` | `fields.level`, `fields.message`; `ip` quando o nginx informa o cliente |
| fail2ban | `found`, `ban`, `unban`, `already_banned` | `fields.jail`; `Restore Ban` conta como `ban` |
| firewall (ufw) | `block`, `allow`, `limit` | `ip` = SRC, `port` = DPT, `fields`: `proto`, `dst`, `src_port`, `in`, `out`. `[UFW AUDIT]` é ignorado |

**Query string nunca é gravada** (costuma levar tokens): é removida de `path` e de `raw`.

## Garantias de entrega
- O agente só avança a posição de leitura **depois que a API confirma** o lote. Reinício, queda da rede ou do ClickHouse não perdem linhas.
- Entrega *at-least-once* com `batch_id`: o mesmo lote reenviado não duplica (a API responde `duplicate: true` e o ClickHouse deduplica por token).
- Rotação (`logrotate`, com criação de arquivo novo ou `copytruncate`) é acompanhada; o fim do arquivo antigo é lido antes de trocar.
- Lote rejeitado com 4xx (ex.: validação) é descartado e registrado no log do agente, para não travar a fila. 5xx, 429, rede e credencial inválida mantêm o lote e repetem.
- Primeira execução lê só linhas novas. Se o arquivo ainda não existe (nginx sem tráfego), é lido do início quando aparecer.
- Se o ClickHouse estiver fora quando a API sobe, a API sobe mesmo assim e tenta criar o esquema a cada 30 s.

## API
- `GET /api/v1/logs` — lista paginada (mais recentes primeiro). Filtros: `server_id`, `source`, `type`, `severity`, `ip`, `q` (busca no texto original), `from`, `to` (padrão: 24 h; máximo 31 dias). Papel mínimo: `viewer`.
- `GET /api/v1/logs/stats` — por fonte/tipo, 10 IPs mais ativos (com bans, bloqueios no firewall e erros HTTP), 10 portas mais bloqueadas, linha do tempo e `traffic` (volume total do nginx a partir dos resumos por minuto).
- `POST /api/v1/agent/logs` — uso do agente (até 500 entradas / 1 MiB).
- Evento SSE `security.ip_banned` (`ip`, `jail`, `banned_at`) para bans recentes do fail2ban (até 20 por lote; ignora bans com mais de 10 min).

Contrato completo em [`api/openapi.yaml`](../api/openapi.yaml).

## Segurança
- Log é **dado controlado por quem ataca** (User-Agent, URL, usuário do SSH). A API remove caracteres de controle, limita tamanhos (`raw` 2048, campos 512) e aceita só vocabulário fechado para `source`/`type`/`severity`. O frontend deve exibir tudo como **texto**, nunca como HTML.
- Consultas ao ClickHouse usam parâmetros tipados (`param_*`); nenhum filtro é concatenado ao SQL.
- O `server_id` vem só da credencial do agente. O token de agente não lê logs (só escreve).
- O agente só **lê** os arquivos (grupo `adm`, `ProtectSystem=strict`) e escreve apenas em `/var/lib/sentinela`.
- O ClickHouse não publica porta no compose (só rede interna). Se expuser, mantenha usuário com senha.

## Operação
- Os logs **não entram no `backup.sh`** (que só faz dump do PostgreSQL): são dados de retenção curta. Para guardá-los, faça backup do volume `chdata` ou use `BACKUP` do ClickHouse.
- Espaço: ~10–20× de compressão sobre texto; o `access_summary` mantém o gráfico de tráfego barato mesmo gravando só erros.
- Métrica Prometheus: `sentinela_log_entries_total{result="stored|duplicate|error"}`.
- Limite por credencial de agente: `AGENT_RATE_LIMIT_PER_SECOND` (2) / `AGENT_RATE_LIMIT_BURST` (10). Ao recuperar um backlog grande o agente pode receber 429 e repete sozinho.
- Limitações: o fim de um arquivo rotacionado enquanto o agente está parado se perde; não há alertas automáticos por rajada de bloqueios no firewall (só o evento de ban).
