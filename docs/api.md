# API

Contrato formal: [`api/openapi.yaml`](../api/openapi.yaml). Só endpoints realmente implementados são documentados; `TestOpenAPIMatchesRouter` falha se o arquivo e o router divergirem.

## Autenticação e autorização
| Grupo | Credencial | Observações |
|---|---|---|
| `/api/v1/**` (usuários) | **Cookie de sessão** (`POST /auth/login`) | Métodos que alteram estado exigem `X-CSRF-Token` (o `csrf_token` do login/`/auth/me`). |
| `/api/v1/**` (automação) | `Authorization: Bearer <ADMIN_API_KEY>` (se configurada) | Papel `admin`, sem cookie/CSRF; auditada como `api_key`. Desativada por padrão. |
| `/api/v1/agent/**` | `Authorization: Bearer snt_…` | Token individual por servidor. |

Papéis `viewer < operator < admin`; cada operação do OpenAPI declara `x-required-role`. Detalhes, bloqueio de login, política de senhas e CSRF em [security.md](security.md). Falta de credencial: **401**; papel insuficiente, CSRF ou origem inválida: **403**.

## Endpoints implementados
| Método | Caminho | Descrição |
|---|---|---|
| GET | /healthz, /readyz, /metrics | Operacionais (sem autenticação; restrinja `/metrics` no proxy) |
| POST | /api/v1/auth/login | Login (pública); cria a sessão |
| POST | /api/v1/auth/logout, /logout-all | Encerra a sessão atual / todas as sessões |
| GET | /api/v1/auth/me | Usuário, papel e `csrf_token` |
| POST | /api/v1/auth/change-password | Troca a própria senha (revoga as outras sessões) |
| GET/POST | /api/v1/users | Listar / criar usuários (admin) |
| GET/PATCH | /api/v1/users/{id} | Detalhe / alterar nome, e-mail, papel, estado, senha (admin) |
| POST | /api/v1/users/{id}/sessions/revoke | Revoga todas as sessões do usuário (admin) |
| GET | /api/v1/audit-logs | Trilha de auditoria (admin) |
| GET/POST | /api/v1/servers | Listar (paginação, busca, filtros, ordenação) / cadastrar |
| GET/PATCH/DELETE | /api/v1/servers/{id} | Detalhe / alterar / exclusão lógica |
| GET | /api/v1/servers/{id}/disks | Volumes (último estado por ponto de montagem) |
| GET/POST | /api/v1/servers/{id}/agent-credentials | Listar (sem token) / emitir (`expires_in_days`, `replace`) |
| DELETE | /api/v1/servers/{id}/agent-credentials/{credentialId} | Revogar |
| GET | /api/v1/servers/{id}/summary | Resumo: última amostra, taxa de rede, discos, alertas, incidentes, serviços e disponibilidade 24 h |
| GET | /api/v1/servers/{id}/metrics | Histórico (`from`, `to`, `interval`) com min/avg/max por balde |
| GET | /api/v1/dashboard/summary | Cards agregados (servidores, alertas, incidentes, CPU, memória, disco) |
| GET | /api/v1/dashboard/metrics | Série agregada entre servidores (`server_id` opcional) |
| GET | /api/v1/dashboard/recent-alerts | Alertas recentes (`limit`, `status`) |
| GET | /api/v1/dashboard/recent-incidents | Incidentes recentes (`limit`, `status`) |
| GET | /api/v1/services | Listar serviços (descobertos automaticamente; filtros) |
| GET | /api/v1/services/{id} | Detalhe |
| GET | /api/v1/servers/{id}/services | Serviços do servidor |
| GET | /api/v1/servers/{id}/discovery | Serviços do sistema descobertos automaticamente (disponibilidade + o que fazer) |
| GET | /api/v1/servers/{id}/incidents | Incidentes do servidor |
| GET/POST | /api/v1/alert-rules | Listar / criar regras de alerta |
| GET/PATCH/DELETE | /api/v1/alert-rules/{id} | Detalhe / alterar / exclusão lógica |
| GET | /api/v1/alerts, /api/v1/alerts/{id} | Listar (filtros) / detalhe |
| POST | /api/v1/alerts/{id}/acknowledge, /resolve | Reconhecer (idempotente) / resolver manualmente |
| GET | /api/v1/incidents, /incidents/{id}, /incidents/{id}/events | Incidentes, detalhe com alertas e linha do tempo |
| GET/POST | /api/v1/notification-channels | Listar / cadastrar canal Telegram |
| GET/PATCH/DELETE | /api/v1/notification-channels/{id} | Detalhe / alterar / remover |
| POST | /api/v1/notification-channels/{id}/test | Enfileira mensagem de teste |
| GET | /api/v1/events | **Stream SSE** de eventos em tempo real (ver [events.md](events.md)); fora do envelope e sem timeout |
| POST | /api/v1/agent/discovery | Serviços do sistema encontrados no host |
| POST | /api/v1/agent/heartbeat |
| POST | /api/v1/agent/metrics | Amostra de métricas (idempotente) |
| GET | /api/v1/agent/config | Parâmetros operacionais do agente |

## Envelope
Sucesso: `{"data": ..., "meta": ...}` (`meta` omitido quando vazio; listagens trazem `page`, `per_page`, `total`, `total_pages`). Erro: `{"error": {"code", "message", "details": []}}`.

| Código | HTTP | Quando |
|---|---|---|
| VALIDATION_ERROR | 422 | Dados inválidos (com `details[].field`) |
| INVALID_JSON / INVALID_ID | 400 | JSON malformado ou com campo desconhecido / UUID inválido |
| UNAUTHORIZED | 401 | Credencial ausente, inválida, expirada ou revogada |
| SERVER_DISABLED | 403 | Servidor com `status=disabled` (agente) |
| NOT_FOUND | 404 | Recurso inexistente ou removido |
| INVALID_STATE | 409 | Alerta já resolvido (reconhecer/resolver) |
| SECRETS_NOT_CONFIGURED | 503 | `SECRETS_KEY` ausente ao gravar token de canal |
| CONFLICT | 409 | Nome de servidor já em uso |
| PAYLOAD_TOO_LARGE | 413 | Acima de `MAX_BODY_BYTES` (64 KiB para agentes) |
| UNSUPPORTED_MEDIA_TYPE | 415 | `Content-Type` diferente de `application/json` |
| RATE_LIMITED | 429 | Limite de agente excedido (`Retry-After`) |
| INVALID_CREDENTIALS | 401 | E-mail ou senha incorretos (resposta única para qualquer falha) |
| LOGIN_LOCKED | 429 | Tentativas demais de login (`Retry-After`) |
| FORBIDDEN | 403 | Papel insuficiente |
| CSRF_INVALID / ORIGIN_NOT_ALLOWED | 403 | Token CSRF ausente/inválido; `Origin` não permitida |
| LAST_ADMIN | 409 | Não se remove/rebaixa o último administrador ativo |
| TOO_MANY_STREAMS | 429 | Limite de streams SSE por endereço |
| STREAM_UNAVAILABLE | 503 | Limite total de streams ou servidor encerrando |
| NOT_READY | 503 | Dependência indisponível (`/readyz`) |
| INTERNAL_ERROR | 500 | Erro interno (sem detalhes) |

Cada resposta traz `X-Request-ID`. `/metrics` é texto Prometheus (fora do envelope).

## Regras de negócio relevantes
- **Conectividade calculada:** `connection_status` = `online` se `now() - last_seen_at <= AGENT_HEARTBEAT_TIMEOUT_SECONDS`, `offline` se maior, `unknown` se nunca houve comunicação. `status` é só o estado administrativo (`active|maintenance|disabled`).
- **Exclusão lógica:** `DELETE` marca `deleted_at`, revoga credenciais e preserva métricas/alertas/incidentes; o nome é liberado.
- **Servidor vem da credencial:** o payload do agente não aceita identificador de servidor (campos desconhecidos → 400).
- **Tempo:** `last_seen_at` usa o relógio do banco (recebimento). `collected_at` do agente é aceito entre 1 h no passado e 2 min no futuro.
- **Idempotência:** reenviar a mesma amostra (mesmo `collected_at`) devolve 200 `duplicate: true`.
- **Servidor `disabled`:** o agente recebe 403. Em `maintenance` continua enviando dados.

## Histórico de métricas (`from`, `to`, `interval`)
- Período `[from, to)` em RFC 3339; padrão: última hora; máximo 90 dias.
- `interval`: `raw`, `1m`, `5m`, `15m`, `1h`, `6h`, `1d`. Baldes alinhados em UTC (origem 2000-01-01), então `1d` = dia UTC.
- **Automático** (sem `interval`): `raw` até 1 h (apenas no endpoint do servidor); acima disso, o menor balde com ≤ 1000 pontos. Ex.: 7 d → 15m, 30 d → 1h, 90 d → 6h.
- Teto de 1000 pontos: pedir um intervalo que geraria mais devolve 422; `raw` denso demais também (nunca trunca em silêncio).
- Cada métrica é `{min, avg, max}` (em `raw` os três são iguais). Valores sem dado (sem swap, primeira amostra sem taxa) são `null`; baldes sem amostras são omitidos — o frontend deve tratar lacunas.
- `meta` informa `interval`, `bucket_seconds` (0 = raw), `points` e `max_points`.

### Taxas de rede
Contadores são acumulados; a taxa de cada amostra é `Δbytes/Δt` em relação à **amostra anterior** e é descartada (`null`) se: for a primeira, o contador diminuiu (reinício/troca de interface) ou a lacuna passou de 10 min. Nos baldes, `avg`/`max` são calculados sobre as taxas válidas. A SQL espelha `metrics.CalcRate` e um teste compara as duas implementações.

## Dashboard — definições dos agregados
| Campo | Definição |
|---|---|
| `servers.online/offline/unknown` | Conectividade calculada (ver acima); `maintenance`/`disabled` são o estado administrativo |
| `resources.*` | Somente servidores **online**, usando a última amostra de cada um (`reporting_servers`) |
| `memory`, `disk` | **Σ usado / Σ total** — não é média de percentuais (um servidor de 64 GB pesa mais que um de 1 GB) |
| `cpu.weighted_avg_percent` | Média ponderada pelo nº de CPUs lógicas (sem contagem = 1) |
| `cpu.distribution` | Servidores com CPU `< 50%` (low), `50–80%` (medium), `≥ 80%` (high) |
| `alerts`, `incidents.open` | Apenas de servidores não removidos |
| `data_as_of` | Recebimento mais recente entre as amostras usadas; `updated_at` = momento do cálculo |

O resumo é calculado em **uma única consulta** (CTEs compartilhadas), sem consulta por card; nenhum cache foi necessário (medido: ~13 ms com 1000 servidores / 600 mil amostras).

## Disponibilidade (`/servers/{id}/summary`)
Janela de 24 h, mas nunca anterior ao cadastro do servidor. Cada amostra recebida em *t* mantém o servidor online até `min(próxima amostra, t + AGENT_HEARTBEAT_TIMEOUT_SECONDS)`; o resto é indisponibilidade. Usa o horário de **recebimento**, não o do agente. `percent` é `null` se a janela tiver menos de 1 minuto.

## Serviços (descoberta automática)
Não há cadastro de serviços: o agente descobre sozinho ssh, systemd-journald, cron, systemd-timesyncd, ufw, rsyslog, nginx, redis, docker e postgresql (veja [agent.md](agent.md)). Cada serviço **que já foi visto disponível** aparece em `/services` com `service_type: "discovered"` e `status` `up`/`down`; quem nunca existiu no servidor só aparece em `GET /servers/{id}/discovery`, com o que fazer para ficar disponível.

Serviços cadastrados manualmente antes dessa mudança (`http`, `tcp`, `systemd`) foram arquivados pela migração `0011` (exclusão lógica, nada foi apagado).

## Regras de alerta
Métricas: `cpu_usage_percent`, `memory_used_percent`, `disk_used_percent` (pior volume; a mensagem cita o ponto de montagem), `load_average_1m`, `server_offline` (valor = segundos sem comunicação) e `service_down` (valor 1 = `down`). `server_id` omitido = regra **global**. A migração `0010` cria uma regra global padrão, **"Serviço indisponível"** (`service_down`, crítica, 120 s para disparar), que cobre os serviços descobertos; as demais métricas não têm regra pré-cadastrada.

## Máquina de estados dos alertas
```
sem alerta ──condição──► pending ──(≥ duration_seconds)──► firing ──condição some──► recuperando ──(≥ recovery_seconds)──► resolved
                          │                                   │  ▲                       │
                          └──condição some──► descartado      │  └───condição volta──────┘
                                                              └──reconhecer──► acknowledged (mesmas transições)
```
- **Alerta × incidente × reconhecimento:** o *alerta* é a ocorrência avaliada pela regra; o *incidente* agrupa a falha contínua (no máximo **um aberto** por servidor+regra+serviço, garantido por índice único); o *reconhecimento* é a ação de um operador e fica como evento do incidente.
- **Deduplicação:** no máximo um alerta ativo por (regra, servidor, serviço) — por índice único parcial e pela máquina de estados. Condição contínua não gera novos alertas, incidentes nem mensagens.
- **Sem dados ≠ recuperado:** se o servidor está offline, métricas de recurso não são avaliadas e um alerta existente **permanece**; `server_offline` cobre a ausência. Serviços verificados pelo agente também só valem com o servidor online.
- **Escopo:** servidores em `maintenance`/`disabled`, removidos, serviços removidos ou regras desativadas/removidas resolvem seus alertas (`resolved_reason`: `out_of_scope`, `rule_disabled`, `rule_deleted`).
- **Resolução manual:** se a condição persistir, um novo alerta nasce após `duration_seconds`.
- **Avaliação:** a cada `ALERT_EVALUATION_INTERVAL_SECONDS` (15 s), sob *advisory lock* (uma instância por vez). Todo o estado (`pending_since`, `recovering_since`) está no banco: reiniciar a API não perde nem reinicia contagens.

## Notificações (Telegram)
- Fila persistente (`notification_outbox`) gravada **na mesma transação** da mudança de estado; chave única `alert:<id>:<triggered|resolved>` por canal impede repetição.
- Canal recebe alertas com severidade ≥ `min_severity` (padrão `critical`). O aviso de recuperação só vai a quem recebeu o disparo.
- Entrega: *lease* + `FOR UPDATE SKIP LOCKED` (várias instâncias, sem duplicar), backoff exponencial 30 s → 30 min com variação, respeita `retry_after` do Telegram, até `NOTIFICATION_MAX_ATTEMPTS` (8). Falhas permanentes (400/401/403) não são retentadas; tudo fica em `last_error` (sem token). Métrica: `sentinela_notifications_total{result}`.
- Segurança: token cifrado com AES-256-GCM (`SECRETS_KEY`, fora do banco), nunca devolvido pela API nem gravado em log/auditoria; `chat_id` precisa estar em `TELEGRAM_ALLOWED_CHAT_IDS` (ou ser o `TELEGRAM_CHAT_ID`) no cadastro **e** no envio. Texto puro, sem `parse_mode`.
