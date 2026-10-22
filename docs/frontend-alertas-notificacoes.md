# Alertas, incidentes e notificações automáticos — guia de migração do front

Alertas e incidentes agora são **automáticos**: as regras vêm de um catálogo fixo no servidor e **não são mais cadastradas pela API**. Toda notificação (alerta, recuperação, IP banido) fica **registrada no PostgreSQL** e pode ser consultada e marcada como lida. Este guia lista o que o front deve **remover** e o que deve **implementar**.

Convenções: base `/api/v1`, envelope `{ "data": ..., "meta": ... }`, mesma autenticação de sempre (cookie + CSRF nas escritas). Contrato completo em `api/openapi.yaml`. Detalhes do catálogo em [alertas-automaticos.md](alertas-automaticos.md).

> Pré-requisito no servidor: API reiniciada com a migração `0013` aplicada e agente atualizado (senão `GET /notifications` ainda não existe e as métricas de sistema não chegam).

---

## 1. Métodos desativados (remover do front)

| Método | Rota | Antes servia para | O que fazer no front |
|---|---|---|---|
| `POST` | `/alert-rules` | Criar regra de alerta | Remover o botão "Nova regra" e o formulário |
| `PATCH` | `/alert-rules/{id}` | Editar limite, severidade, duração, ativar/desativar | Remover a edição e o interruptor "ativa" |
| `DELETE` | `/alert-rules/{id}` | Excluir regra | Remover o botão de excluir |

Qualquer chamada a elas responde `404`/`405`.

Também deixaram de existir:

- **Regras por servidor.** `server_id` de uma regra é sempre `null` (todas valem para todos os servidores). Remova o seletor "aplicar a: servidor X" e o filtro `?server_id=` em `GET /alert-rules` (o parâmetro foi retirado).
- **Campos de escrita da regra** (`CreateAlertRule` / `UpdateAlertRule`): `threshold`, `operator`, `duration_seconds`, `recovery_seconds`, `is_enabled` agora são **somente leitura**. Exiba, mas não envie.
- **Regras antigas cadastradas à mão** foram **arquivadas** (não aparecem mais em `GET /alert-rules`). Os alertas e incidentes delas continuam no histórico.
- **Canal sem filtro de gravidade como padrão.** `min_severity` de um canal novo agora é `info` (recebe tudo). Se a tela de canais mostrava `critical` como valor inicial, troque.
- **Auditoria:** ações `alert_rule.create|update|delete` deixaram de ser geradas (o histórico antigo continua). Remova-as de filtros/legendas novos, mas mantenha o rótulo para exibir registros antigos.

> Dica: busque no código do front por `alert-rules`, `CreateAlertRule`, `UpdateAlertRule`, `RuleForm` e `is_enabled`.

---

## 2. Métodos que continuam

| Método | Rota | Papel mínimo | Mudança |
|---|---|---|---|
| `GET` | `/alert-rules` | viewer | **Somente leitura.** Novos campos e filtro `priority` (abaixo) |
| `GET` | `/alert-rules/{id}` | viewer | igual |
| `GET` | `/alerts`, `/alerts/{id}` | viewer | Novo campo `priority` |
| `POST` | `/alerts/{id}/acknowledge` | operator | sem mudança |
| `POST` | `/alerts/{id}/resolve` | operator | sem mudança |
| `GET` | `/incidents`, `/incidents/{id}`, `/incidents/{id}/events`, `/servers/{id}/incidents` | viewer | Novos campos `priority`, `recurrence_count`; filtro `priority`; novo tipo de evento `recurrent` |
| `*` | `/notification-channels...` | admin | sem mudança de rotas; só o padrão de `min_severity` |

---

## 3. Prioridades (P1–P4)

Campo inteiro `priority` em regras, alertas, incidentes e notificações.

| `priority` | Nome | `severity` equivalente | Sugestão de cor | Ação |
|---|---|---|---|---|
| `1` | P1 — Crítico | `critical` | vermelho | notificação imediata |
| `2` | P2 — Alto | `critical` | laranja | notificar rápido e investigar |
| `3` | P3 — Atenção | `warning` | amarelo | corrigir antes de virar incidente |
| `4` | P4 — Informativo | `info` | azul | só histórico |

P1 e P2 têm a mesma `severity` (`critical`); **use `priority` para ordenar e colorir**, e `severity` apenas por compatibilidade. Recuperações são sempre P4; IPs banidos são P3.

---

## 4. Regras automáticas (`GET /alert-rules`)

Lista ordenada por prioridade. Filtros: `page`, `per_page` (máx. 100), `metric_name`, `severity`, `priority` (`1`–`4`), `enabled`.

```json
{
  "id": "…uuid…",
  "code": "cpu_high",
  "name": "CPU em uso excessivo",
  "description": "A CPU ficou acima de 90% por 5 minutos.",
  "metric_name": "cpu_usage_percent",
  "operator": ">",
  "threshold": 90,
  "priority": 2,
  "severity": "critical",
  "duration_seconds": 300,
  "recovery_seconds": 120,
  "server_id": null,
  "is_enabled": true,
  "created_at": "…", "updated_at": "…"
}
```

Use `code` como chave estável (o `id` é gerado no banco). `duration_seconds` = tempo com a condição verdadeira antes de alertar; `recovery_seconds` = tempo normalizado antes de resolver. Mostre a tela de regras como **"o que o Sentinela vigia"** (informativa, sem botões de edição).

| `code` | P | Condição | Dispara após | Resolve após |
|---|---|---|---|---|
| `server_offline` | 1 | sem comunicação há mais de 120 s | imediato | 60 s |
| `service_down` | 1 | serviço descoberto parado | 120 s | 60 s |
| `disk_critical` | 1 | disco > 95 % | 60 s | 120 s |
| `memory_low` | 2 | RAM em uso > 90 % | 120 s | 120 s |
| `cpu_high` | 2 | CPU > 90 % | 300 s | 120 s |
| `load_high` | 2 | load (1 min) > 2 × CPUs | 300 s | 120 s |
| `oom_kill` | 2 | OOM Killer ativo (10 min) | imediato | 60 s |
| `inodes_high` | 2 | inodes > 90 % | 120 s | 300 s |
| `cert_critical` | 2 | certificado vence em < 2 dias | imediato | 1 h |
| `disk_high` | 3 | disco > 80 % | 300 s | 300 s |
| `swap_high` | 3 | swap > 50 % | 600 s | 300 s |
| `disk_latency` | 3 | latência de disco > 200 ms | 300 s | 300 s |
| `cert_expiring` | 3 | certificado vence em < 7 dias | imediato | 1 h |
| `ntp_unsynchronized` | 3 | relógio sem sincronizar | 600 s | 300 s |
| `security_updates` | 3 | atualizações de segurança pendentes | 1 h | 300 s |

`metric_name` agora também aceita: `swap_used_percent`, `load_per_cpu`, `oom_kills_10m`, `inode_used_percent`, `disk_latency_ms`, `ntp_unsynchronized`, `security_updates`, `cert_days_left`. Se o front tem um mapa de rótulos por métrica, acrescente esses.

---

## 5. Alertas e incidentes (campos novos)

**Alerta** (`GET /alerts`, `/alerts/{id}`): novo campo `priority` (1–4). O resto não mudou.

**Incidente** (`GET /incidents...`):

| Campo | Tipo | Descrição |
|---|---|---|
| `priority` | integer 1–4 | herdada da regra |
| `recurrence_count` | integer | incidentes iguais (mesmo servidor, regra e serviço) resolvidos nas 24 h anteriores à abertura. **> 0 = reincidente** |

Sugestões de UI: selo **"Reincidente (N×)"** quando `recurrence_count > 0`; filtro por prioridade (`?priority=1`); ordenar a lista por `priority` e depois `started_at`.

`GET /incidents/{id}/events` ganhou o tipo `event_type: "recurrent"` (mensagem tipo "Reincidente: 2 incidente(s) igual(is) resolvido(s) nas últimas 24 h"). Tipos existentes: `opened`, `alert_triggered`, `acknowledged`, `alert_resolved`, `resolved`, `recurrent`.

O texto de abertura agora inclui a prioridade: `"Incidente aberto (P1): …"`.

---

## 6. Notificações (novo)

Registro permanente no PostgreSQL de **todo** aviso gerado: alerta disparado, alerta recuperado e IP banido pelo fail2ban. Existe mesmo sem canal do Telegram configurado e mesmo que a entrega falhe. É o histórico para a tela/sino de notificações do painel.

### `GET /notifications` — papel mínimo: viewer

Mais recentes primeiro.

| Parâmetro | Tipo | Descrição |
|---|---|---|
| `page`, `per_page` | integer | paginação (máx. 100) |
| `kind` | `alert_triggered` \| `alert_resolved` \| `ip_banned` | tipo |
| `priority` | `1`–`4` | prioridade |
| `server_id` | uuid | servidor |
| `unread` | `true` | só as não lidas |
| `from`, `to` | RFC 3339 | período por `created_at` |

Resposta `200`:

```json
{
  "data": [
    {
      "id": 42,
      "kind": "alert_triggered",
      "priority": 1,
      "severity": "critical",
      "server_id": "…uuid…",
      "server_name": "web-1",
      "alert_id": "…uuid…",
      "incident_id": "…uuid…",
      "title": "Servidor sem comunicação — web-1",
      "message": "Sem comunicação há 3 min 20 s (limite: > 2 min 0 s)",
      "data": { "…": "cópia do conteúdo enviado" },
      "created_at": "2026-03-01T12:00:00Z",
      "read_at": null
    }
  ],
  "meta": { "page": 1, "per_page": 20, "total": 120, "total_pages": 6, "unread": 7 }
}
```

- **`meta.unread`** = total de não lidas **de todas as notificações**, ignorando os filtros. Use no contador (badge) do sino.
- Lidas = `meta.total - meta.unread` somente quando **não há filtro**. Com filtros, `meta.total` é só o recorte.
- `alert_id` / `incident_id` / `server_id` podem ser `null` (ex.: ban não tem alerta). Use para criar links para `/alerts/{id}`, `/incidents/{id}` e o servidor.

| `kind` | `title` | `priority` / `severity` |
|---|---|---|
| `alert_triggered` | `"<regra> — <servidor>"` (ou `"<regra> — <serviço> — <servidor>"`) | a da regra |
| `alert_resolved` | `"Recuperado: <regra> — <servidor>"` | sempre `4` / `info` |
| `ip_banned` | `"IP banido: <ip> — <servidor>"` | sempre `3` / `warning` |

### `POST /notifications/{id}/read` — papel mínimo: operator

Marca uma como lida. **Idempotente:** marcar de novo não troca `read_at` nem quem marcou. `200` com a notificação atualizada, `404` se não existir, `400` se o `id` não for inteiro.

### `POST /notifications/read-all` — papel mínimo: operator

Marca todas como lidas. `200` com `{ "data": { "marked": 12 } }` (quantas mudaram).

### Regras de comportamento

- A marcação como lida é **global** (compartilhada por todos os usuários do painel). Não há "marcar como não lida".
- Viewer **lista** mas não **marca** como lida (esconda os botões para esse papel; a API devolve `403`).
- `id` é número inteiro (não UUID).

### Tempo real

Não existe evento SSE `notification.created`. Para manter o sino atualizado, escute os eventos que já existem e **refaça `GET /notifications?per_page=…`** (ou só atualize o contador) quando chegarem:

```ts
const es = new EventSource(
  "/api/v1/events?types=alert.triggered,alert.resolved,security.ip_banned",
  { withCredentials: true });
const refresh = () => queryClient.invalidateQueries({ queryKey: ["notifications"] });
["alert.triggered", "alert.resolved", "security.ip_banned"].forEach(t => es.addEventListener(t, refresh));
es.addEventListener("resync", refresh);
```

(`GET /notifications` também funciona bem com polling a cada 30–60 s como reserva.)

---

## 7. Canais de notificação (Telegram)

Rotas inalteradas (`/notification-channels...`, papel admin). O que muda:

- **Todo tipo de alerta chega ao Telegram:** P1 a P4, recuperações e bans. O `min_severity` padrão é `info`; a migração `0013` também ajusta os canais já existentes para `info`.
- Quem quiser menos mensagens pode subir o `min_severity` do canal (`warning` corta P4; `critical` corta P3 e P4). **O registro em `GET /notifications` não é afetado** pelo filtro do canal.
- Formato da mensagem: `🔴 [P1 · crítico] web-1 (reincidente: 2× em 24 h)`; bans: `🚫 [P3 · aviso] web-1 — IP banido pelo fail2ban: 203.0.113.9`; recuperação: `✅ [RECUPERADO] web-1`.

---

## 8. Resumo para o checklist do front

**Remover**
- [ ] Botão/formulário de criar regra (`POST /alert-rules`)
- [ ] Edição, ativar/desativar e excluir regra (`PATCH`/`DELETE /alert-rules/{id}`)
- [ ] Seletor "aplicar a servidor" e filtro `server_id` em regras
- [ ] Valor inicial `critical` no campo `min_severity` de canais (agora `info`)

**Implementar**
- [ ] Tela de regras somente leitura, agrupada por `priority`, usando `code`, `name`, `description`, `threshold`, `duration_seconds`
- [ ] Selo de prioridade P1–P4 em alertas, incidentes e notificações
- [ ] Selo "Reincidente (N×)" e filtro por prioridade nos incidentes; evento `recurrent` na linha do tempo
- [ ] Rótulos para as novas `metric_name`
- [ ] Sino/tela de notificações: lista paginada, filtros (`kind`, `priority`, `server_id`, `unread`, período), contador `meta.unread`
- [ ] Marcar como lida (uma / todas), só para operator e admin
- [ ] Atualização do sino via SSE (`alert.triggered`, `alert.resolved`, `security.ip_banned`) com refetch
- [ ] Links de cada notificação para alerta, incidente e servidor
