# Eventos em tempo real (SSE)

`GET /api/v1/events` — *Server-Sent Events*, unidirecional (servidor → cliente). Contrato completo em [`api/openapi.yaml`](../api/openapi.yaml).

## Formato
```
retry: 5000
: connected

id: 7
event: alert.triggered
data: {"id":7,"type":"alert.triggered","time":"2026-03-01T12:00:00Z","data":{"alert_id":"…","server_name":"web-1","severity":"critical",…}}

: ping
```
- `data:` é sempre **uma linha** de JSON: `{id?, type, time, data}`.
- `: ping` a cada 15 s (`SSE_HEARTBEAT_SECONDS`) mantém proxies abertos e permite detectar cliente morto.
- Eventos **efêmeros** (`metrics.updated`) não têm `id`, para não alterar o `Last-Event-ID` guardado pelo navegador.

## Eventos
| Tipo | Quando | Durável | Origem |
|---|---|---|---|
| `server.status_changed` | servidor ficou online/offline (≤ 5 s) ou mudou o estado administrativo | sim | monitor de conectividade / `PATCH /servers/{id}` |
| `service.status_changed` | serviço mudou de estado (unknown/up/down/degraded) | sim | verificação central ou relatório do agente |
| `alert.triggered` / `alert.acknowledged` / `alert.resolved` | transições do alerta | sim | avaliador / API |
| `incident.created` / `incident.resolved` | abertura e fechamento | sim | avaliador / API |
| `security.ip_banned` | o fail2ban baniu um IP (`ip`, `jail`, `banned_at`; só bans recentes) | sim | ingestão de logs do agente ([logs.md](logs.md)) |
| `metrics.updated` | nova amostra de um servidor (máx. 1 a cada 5 s por servidor) | **não** | ingestão do agente |
| `resync` | o cliente deve recarregar o estado pela API (`reason`: `gap`, `ahead`, `too_many`, `overflow`, `error`) | — | sintético |

Filtros: `?types=a,b` (padrão: todos os duráveis; **`metrics.updated` é opt-in** por ser de alta frequência) e `?server_id=<uuid>`.

## Reconexão sem perder eventos
1. O cliente guarda o último `id` recebido. O `EventSource` envia `Last-Event-ID` sozinho; clientes baseados em `fetch` usam `?last_event_id=`.
2. O servidor **assina o fluxo ao vivo primeiro**, depois lê o histórico e reenvia `id > Last-Event-ID` em ordem; eventos que aparecem nos dois lados são descartados pelo `id`. Resultado: sem buracos e sem duplicatas.
3. `resync` quando: o histórico foi removido pela retenção (`gap`, janela de `EVENTS_RETENTION_HOURS` = 24 h), o id não existe neste histórico (`ahead`), faltam mais de 1000 eventos (`too_many`), ou o cliente é lento demais (`overflow`, desconectado em seguida). Ao receber `resync`, recarregue com a API REST e continue ouvindo.
4. Sem `Last-Event-ID`: só chegam eventos novos.

## Autorização
- **Sessão de usuário (cookie `HttpOnly`)**: o `EventSource` nativo funciona com `withCredentials: true` — não precisa de cabeçalhos. Qualquer papel (`viewer` ou acima) pode ouvir. Também aceita `Authorization: Bearer <ADMIN_API_KEY>` (clientes baseados em `fetch`).
- **Revalidação:** a cada `: ping` o servidor reavalia a sessão; sessão revogada, vencida ou usuário desativado **encerra o stream** (no máximo `SSE_HEARTBEAT_SECONDS` depois).
- Política: todo usuário autenticado vê os mesmos eventos (aplicação de um único tenant). O ponto de extensão para filtrar por papel é `events.Filter`/`Hub.Subscribe`.
- Os payloads são mínimos e **não contêm** tokens, segredos, alvos/URLs de serviços, hostnames, mensagens de erro brutas nem notas de operadores (há teste que varre o log de eventos).

```ts
// EventSource nativo (cookie de sessão): reconecta sozinho e reenvia Last-Event-ID
const es = new EventSource("/api/v1/events?types=alert.triggered,alert.resolved,server.status_changed", { withCredentials: true });
es.addEventListener("resync", () => queryClient.invalidateQueries());          // recarregue o estado pela API
es.onmessage = ...; es.addEventListener("alert.triggered", (m) => { const ev = JSON.parse(m.data); /* {id,type,time,data} */ });
```

Frontend em outro site: `COOKIE_SAMESITE=none`, `COOKIE_SECURE=true` e a origem em `CORS_ALLOWED_ORIGINS`.


## Como funciona por dentro
- **Log durável:** tabela `events`, gravada **na mesma transação** da mudança (rollback ⇒ sem evento). Depois do commit, `pg_notify` acorda os hubs.
- **Várias instâncias sem broker:** cada instância tem um `Hub` com uma conexão `LISTEN` dedicada (+1 conexão ao banco por instância, fora do pool) e distribui aos seus clientes. Se um `NOTIFY` se perder, um *poll* a cada 5 s recupera; se a conexão cair, o hub reconecta (backoff 1→15 s) e recupera pelo log. Os canais incluem o schema (`sentinela_events_<schema>`), pois `LISTEN/NOTIFY` é global ao banco.
- **Ordem correta:** ids vêm de uma sequência, que não segue a ordem de commit; um cursor por id poderia pular um evento de transação lenta. `events.Publish` toma um *advisory lock* de transação, então a publicação é serializada e os ids seguem a ordem de commit. **Regra:** chame `Publish` por último na transação (depois das escritas que disputam linhas), para não criar deadlock.
- **Redis:** não é necessário. Se um dia o volume exigir, o ponto de troca é `Hub.listen`/`events.Publish`; o log durável continuaria sendo a fonte de verdade para o replay.
- **Cliente lento:** cada assinatura tem buffer de 256 eventos; ao encher, o cliente é desconectado com `resync` (o `Broadcast` nunca bloqueia).
- **Recursos:** a assinatura é liberada em qualquer saída do handler (`defer`); no desligamento, `Server.RegisterOnShutdown(hub.Close)` encerra os streams (sem isso o `Shutdown` esperaria o timeout).
- **Timeouts:** a rota fica fora do timeout por requisição e cada escrita ganha seu prazo (`ResponseController.SetWriteDeadline`), pois o `WriteTimeout` do servidor (30 s) mataria o stream.

## Operação
- Métricas: `sentinela_sse_clients` (conexões abertas), `sentinela_sse_events_total{result=delivered|overflow}`, `sentinela_job_duration_seconds{job="server_connectivity"}`.
- Limites: `SSE_MAX_CLIENTS` (500), `SSE_MAX_CLIENTS_PER_IP` (20). Atrás de Nginx, ative `TRUST_PROXY=true` para o limite por IP usar `X-Real-IP`.
- Nginx:
  ```nginx
  location /api/v1/events {
      proxy_pass http://127.0.0.1:8080;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_set_header X-Real-IP $remote_addr;
      proxy_buffering off;            # a API também envia X-Accel-Buffering: no
      proxy_cache off;
      proxy_read_timeout 1h;          # bem acima do heartbeat de 15 s
  }
  ```
