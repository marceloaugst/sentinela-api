# Arquitetura do Sentinela

## Componentes
- **API central** (`cmd/api`): REST em Go + Chi, PostgreSQL via pgx, logs `slog`, métricas Prometheus.
- **Agente** (`cmd/agent`): binário independente instalado nos servidores. Na Fase 1 é só um esqueleto.
- **PostgreSQL**: único armazenamento obrigatório. Redis é opcional (profile `redis` do compose) e só será usado com necessidade concreta.

## Camadas
`handlers` (HTTP) → serviços de domínio (regras de negócio, por módulo em `internal/<modulo>`) → repositórios (pgx). Interfaces só onde facilitam testes (ex.: `handlers.Pinger`).

## Decisões da Fase 1
| Tema | Decisão |
|---|---|
| Migrações | SQL puro em `migrations/NNNN_nome.{up,down}.sql`, embutido no binário (`embed`). Runner próprio com `schema_migrations` e `pg_advisory_xact_lock` (seguro contra instâncias concorrentes). `AUTO_MIGRATE=true` ou `sentinela-api migrate`. |
| Envelope | Sucesso `{data, meta}`; erro `{error:{code,message,details[]}}`. Erros internos nunca expõem stack nem detalhes de banco. |
| Config | Somente variáveis de ambiente, validadas na subida (todos os erros agregados). |
| Observabilidade | `/healthz` (liveness), `/readyz` (ping do Postgres, 503 sem detalhes), `/metrics` (métricas **da API**, namespace `sentinela_`). |
| Pool | `DB_MAX_CONNS`/`DB_MIN_CONNS`, estatísticas do pool exportadas. |

## Decisões da Fase 2
| Tema | Decisão |
|---|---|
| Proteção do admin | *(substituída na Fase 6 por usuários, sessões e papéis; veja abaixo)* A chave estática `ADMIN_API_KEY` continua existindo apenas como credencial de automação opcional, desativada por padrão. |
| Credencial de agente | `snt_` + 256 bits aleatórios; guarda-se SHA-256. Emitir com `replace` revoga as anteriores na mesma transação. Servidor excluído/desativado invalida o acesso. `last_used_at` é atualizado no máximo 1×/min. |
| Isolamento | O `server_id` vem só da credencial; `DisallowUnknownFields` rejeita tentativas de enviar outro identificador. |
| Rate limiting | Token bucket em memória: por IP (antes de consultar o banco, contém tentativas com token inválido) e por credencial (`AGENT_RATE_LIMIT_*`); o limite por IP é `AGENT_IP_RATE_LIMIT_*` (20/s, rajada 60). Limitação: o estado é por instância; com várias instâncias da API, usar Redis (fase futura). IP real só com `TRUST_PROXY=true` atrás do Nginx (`X-Real-IP`). |
| Idempotência | `INSERT ... ON CONFLICT (server_id, collected_at) DO NOTHING`; reenvio devolve `duplicate: true`. Testado com 20 gravações concorrentes da mesma amostra. |
| Discos | UPSERT por `(server_id, mount_point)` só se a amostra não for mais antiga que a gravada; volumes ausentes na coleta mais recente são removidos. |
| Auditoria | Gravada na **mesma transação** da ação; chaves com `token/password/secret/key/hash` são sobrescritas por `[redacted]`. |
| Inventário | `hostname` é definido pelo administrador; o agente atualiza apenas SO, versão do SO, arquitetura e versão do agente. |
| Testes de integração | Cada teste usa um schema PostgreSQL exclusivo (`search_path`), permitindo pacotes em paralelo no mesmo banco. |

## Decisões da Fase 3
| Tema | Decisão |
|---|---|
| Agregação temporal | `date_bin` do PostgreSQL com origem fixa em UTC; uma única consulta com janelas (`lag`) calcula taxas de rede e agrega min/avg/max. Sem tabelas de rollup por ora: medido via HTTP, 7 dias de um servidor (40.320 amostras a cada 15 s) respondem em ~0,2–0,3 s. Se isso virar gargalo (muitos usuários no mesmo gráfico longo), o passo seguinte é uma tabela de agregados de 5 min alimentada pelo job de retenção. |
| Limite de pontos | `MaxPoints = 1000` aplicado na validação (intervalo × período) e na consulta (`LIMIT 1001` detecta excesso). |
| Dashboard | Um `SELECT` com CTEs (`srv`, `lat` via `LATERAL` + `LIMIT 1` pela PK, `act`). Verificado com `EXPLAIN ANALYZE`: usa `server_metrics_pkey`. |
| Retenção | `internal/retention`: a cada `RETENTION_INTERVAL_MINUTES`, apaga em lotes de 10 mil linhas (`DELETE ... IN (SELECT ... LIMIT)` pela PK) o que for mais antigo que `METRICS_RETENTION_DAYS`. `pg_try_advisory_lock` garante uma execução por vez entre instâncias. Métricas: `sentinela_job_duration_seconds`, `sentinela_retention_deleted_rows_total`. |
| Observabilidade | `sentinela_agent_samples_total{result=stored|duplicate}` mede o volume de amostras recebidas. |
| Particionamento | Ainda não necessário. Gatilho para adotar: > ~100 milhões de linhas ou limpeza que não acompanhe a ingestão. Então converter `server_metrics` em partições mensais por `collected_at` (a retenção passa a ser `DROP PARTITION`). |

## Decisões da Fase 4
| Tema | Decisão |
|---|---|
| Serviços | Sem cadastro: o agente descobre os serviços do sistema e envia fatos (`POST /agent/discovery`); a API espelha em `monitored_services` (tipo `discovered`) para alertas e incidentes. Todo serviço tem `server_id` obrigatório. |
| Avaliador de alertas | Função pura `Decide` (tabela de transições testada) + efeitos transacionais. Um *snapshot* compartilhado (servidores ativos + serviços) alimenta todas as regras: poucas consultas por ciclo. Lock consultivo de sessão garante uma instância avaliando. |
| Estado persistido | `alerts.pending_since` / `recovering_since`; `pending` é invisível na API e fora dos agregados do dashboard. |
| Incidentes | Aberto na promoção a `firing`, fechado ao resolver o alerta; eventos em `incident_events` (opened, alert_triggered, acknowledged, alert_resolved, resolved). |
| Notificações | *Outbox* na mesma transação da transição; *worker* com lease e backoff; dedup por `(canal, alert:<id>:<tipo>)`. |
| Segredos | AES-256-GCM com AAD fixa; chave só em variável de ambiente. Sem chave: a API recusa criar canais (503) e o worker não envia. |
| Tarefas em segundo plano | `scheduler.Loop`: sem sobreposição, isola erro/panic e mede duração (`sentinela_job_duration_seconds{job}`): retenção, verificação de serviços, avaliação de alertas e notificações. |
| Atores | O autor de reconhecimentos/alterações é o usuário da sessão (`acknowledged_by` guarda o id; fica nulo quando a ação vem da `ADMIN_API_KEY` de automação; o ator consta no evento e na auditoria). |

## Decisões da Fase 5
| Tema | Decisão |
|---|---|
| Transporte | SSE sobre HTTP (unidirecional), conforme a especificação. Sem WebSocket. |
| Fonte de verdade | Tabela `events` (log durável) gravada na transação da mudança; `NOTIFY` só acorda os hubs. Permite `Last-Event-ID` e várias instâncias sem Redis. |
| Ordem | `events.Publish` serializa por *advisory lock* de transação ⇒ ids em ordem de commit ⇒ cursor por id é seguro. Regra de uso: publicar por último na transação. |
| Efêmeros | `metrics.updated` só via `NOTIFY` (sem gravar), limitado a 1/5 s por servidor e opt-in. |
| Conectividade | `servers.connection_state` guarda o último estado observado; o monitor (5 s, sob lock) publica as transições. A API continua calculando o estado por `last_seen_at`. |
| Falhas | Reconexão do LISTEN com backoff + pull de recuperação + poll de segurança; cliente lento recebe `resync` e é desconectado. |
| Retenção | `EVENTS_RETENTION_HOURS` (24 h); `event_log_state.purged_until` permite saber com certeza se um cliente perdeu eventos. |
| Segurança | Mesma chave admin (Fase 6: sessão); payloads sem segredos/alvos/hostnames; limites por IP e total; chave nunca na URL. |

## Decisões da Fase 6
| Tema | Decisão |
|---|---|
| Sessão | Opaca, no banco (hash SHA-256), cookie `HttpOnly`/`Secure`/`SameSite`, prefixo `__Host-` em produção; prazo absoluto + inatividade deslizante; token novo a cada login e troca de senha. |
| CSRF | Token derivado por HMAC do token da sessão (sem estado) em `X-CSRF-Token` + checagem de `Origin`; só para cookie (a chave de API não usa cookie). |
| Senhas | Argon2id com parâmetros no hash (rehash no login), concorrência limitada, hash "fantasma" para igualar o tempo de contas inexistentes. |
| Autorização | `viewer < operator < admin`, **declarada por rota** em um único lugar (`router.go`), que alimenta o registro usado nos testes de matriz e a conferência do OpenAPI (`x-required-role`). Papel e estado do usuário são lidos do banco a cada requisição. |
| Bloqueio de login | Três escopos (e-mail+IP, IP, e-mail) calculados sobre `login_attempts`, antes da senha; se desfaz pelo tempo. |
| Revogação | Desativar/redefinir senha revoga sessões na mesma transação; SSE revalida a sessão a cada ping. |
| `ADMIN_API_KEY` | Mantida como credencial de **automação** opcional e desativada por padrão (não substitui usuários). |
| Auditoria | `audit.Context` leva `UserID`/ator; gravada na transação da ação; `GET /audit-logs`; retenção configurável. |
| Operação | Primeiro admin por `create-admin`/bootstrap; `reset-password` por CLI; limpeza periódica de sessões/tentativas/auditoria; limites de taxa por IP; cabeçalhos de segurança; `/metrics` com token opcional. |

## Decisões para fases futuras (documentadas agora)
**Autenticação de usuários:** implementada na Fase 6 (ver abaixo e [security.md](security.md)).

**Credenciais de agente:** token aleatório de 256 bits exibido uma única vez; armazena-se SHA-256 (entropia alta dispensa KDF lento). Uma credencial por servidor, revogável e com expiração opcional. O `server_id` vem sempre da credencial, nunca do payload.

**Status do servidor:** `servers.status` é estado *administrativo* (`active|maintenance|disabled`). Online/offline é **calculado**: `now() - last_seen_at <= AGENT_HEARTBEAT_TIMEOUT_SECONDS`, usando o horário de recebimento (`received_at`), não o do agente.

**Exclusão e retenção:** servidor é removido logicamente (`deleted_at`); métricas, alertas e incidentes são preservados. Métricas expiram após `METRICS_RETENTION_DAYS` por job de limpeza. Para escala, `server_metrics` pode ser convertida em tabela particionada por `collected_at` (a PK já começa por `server_id`; a conversão exige incluir a chave de partição, o que já é o caso com `collected_at`).

**Métricas:** `UNIQUE (server_id, collected_at)` rejeita reenvio da mesma amostra. Contadores de rede são acumulados; taxas = Δbytes/Δt entre amostras consecutivas, descartando Δ negativo (reset) e intervalos inválidos. "Memória usada" = `total - available` (conceito `MemAvailable` do Linux, que considera cache recuperável). Discos: um registro atual por `(server_id, mount_point)` via UPSERT.

**Agregados do dashboard:** utilização global de memória = Σused / Σtotal; CPU é apresentada como distribuição (média ponderada por CPUs lógicas, máx., contagem acima do limiar), nunca como média simples enganosa.

**Alerta × incidente × reconhecimento:** *alerta* = ocorrência de uma regra para um servidor/serviço (máquina de estados `pending→firing→acknowledged→resolved`); *incidente* = agrupamento da falha contínua, no máximo um aberto por (servidor, regra, serviço) — garantido por índice único parcial; *reconhecimento* = ação de um usuário sobre um alerta (`acknowledged_by/at`). Deduplicação por índice único parcial em `alerts`.

**Notificações:** outbox persistente (`notification_outbox`) com `dedup_key` único por canal e backoff; tokens cifrados (AES-GCM) com chave fornecida por variável de ambiente.

## Modelo de dados (migrações)
| Migração | Tabelas |
|---|---|
| 0001 | users, sessions, login_attempts |
| 0002 | servers, agent_credentials |
| 0003 | server_metrics, server_disks |
| 0004 | monitored_services, alert_rules, incidents, incident_events, alerts |
| 0012 | alertas automáticos: `alert_rules.code/description/priority`, `incidents.priority/recurrence_count` |
| 0013 | tabela `notifications` (registro permanente) e métricas de sistema no catálogo de alertas |
| 0005 | notification_channels, notification_outbox, audit_logs |
