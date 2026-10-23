# Alertas e incidentes automáticos

Nada é cadastrado: as regras são um **catálogo fixo no código** (`internal/alerts/catalog.go`). A cada
inicialização a API grava o catálogo no PostgreSQL (`alert_rules`, upsert pelo `code`) e **arquiva** qualquer
regra fora dele (por exemplo, as criadas à mão antes). Mudar um limite = mudar o código e reiniciar a API.
`GET /api/v1/alert-rules` é somente leitura (filtros `priority`, `metric_name`, `severity`, `enabled`).

Tudo é gravado no PostgreSQL do compose (serviço `postgres`): `alert_rules`, `alerts`, `incidents`,
`incident_events`, `notification_outbox`.

## Prioridades

| Prioridade | Severidade | Ação |
|---|---|---|
| P1 crítico | `critical` | Notificação imediata |
| P2 alto | `critical` | Notificar rapidamente e investigar |
| P3 atenção | `warning` | Aparece no painel; corrigir antes de virar incidente |
| P4 informativo | `info` | Histórico (recuperações ficam na linha do tempo do incidente) |

**Todo tipo de alerta vira notificação**, de P1 a P4, e a recuperação também (registrada como P4). Os canais
(Telegram) recebem tudo por padrão: `min_severity` agora é `info`, e a migração `0013` ajustou os canais já
existentes. Quem quiser menos ruído pode subir o `min_severity` do canal; o registro no banco não é afetado.

## Catálogo atual

| Código | Prioridade | Condição | Dispara após | Resolve após |
|---|---|---|---|---|
| `server_offline` | P1 | sem comunicação há mais de 120 s | imediato | 60 s |
| `service_down` | P1 | serviço descoberto (Nginx, PostgreSQL, Redis...) indisponível | 120 s | 60 s |
| `disk_critical` | P1 | disco > 95 % | 60 s | 120 s |
| `memory_low` | P2 | RAM em uso > 90 % (disponível < 10 %) | 120 s | 120 s |
| `cpu_high` | P2 | CPU > 90 % | 300 s | 120 s |
| `load_high` | P2 | load average (1 min) > 2 × CPUs | 300 s | 120 s |
| `disk_high` | P3 | disco > 80 % | 300 s | 300 s |
| `swap_high` | P3 | swap em uso > 50 % | 600 s | 300 s |
| `oom_kill` | P2 | OOM Killer encerrou processos nos últimos 10 min | imediato | 60 s |
| `inodes_high` | P2 | inodes > 90 % em algum volume | 120 s | 300 s |
| `cert_critical` | P2 | certificado vence em menos de 2 dias (ou venceu) | imediato | 1 h |
| `disk_latency` | P3 | latência de disco > 200 ms | 300 s | 300 s |
| `cert_expiring` | P3 | certificado vence em menos de 7 dias | imediato | 1 h |
| `ntp_unsynchronized` | P3 | relógio sem sincronizar (systemd-timesyncd) | 600 s | 300 s |
| `security_updates` | P3 | atualizações de segurança pendentes | 1 h | 300 s |

As seis últimas linhas de cima (OOM em diante) vêm de **métricas de sistema guardadas no ClickHouse**
(tabela `system_metrics`, retenção `LOGS_RETENTION_DAYS`). Se o ClickHouse estiver fora do ar, esses alertas
não abrem nem resolvem até o dado voltar.

## Quem consumiu (processos)

`cpu_high`, `load_high`, `memory_low`, `swap_high` e `oom_kill` anexam ao alerta os **3 maiores consumidores** (CPU ou memória, conforme a regra):
o texto vai na mensagem do alerta, do incidente e da notificação, e o dado estruturado em `alerts.culprits` (veja [frontend-processos.md](frontend-processos.md)).
O agente envia os processos a cada ~30 s (~10 s com CPU ou RAM acima de 85 %); a API grava no ClickHouse (`process_top`) os 5 maiores por CPU e por memória de cada leitura.
Ao disparar, o avaliador calcula a média por nome de processo sobre a janela em que a condição valia (a duração da regra, de 2 a 15 min).
Sem ClickHouse ou sem histórico, usa a última leitura de processos se tiver menos de 2 min; sem nada, o alerta dispara sem a lista (nunca atrasa nem falha por isso).
O histórico também pode ser consultado direto: `GET /servers/{id}/processes/history`.

## Métricas de sistema (agente → ClickHouse)

A cada minuto o agente lê `/proc/vmstat` (OOM), `/proc/diskstats` (latência), `statfs` (inodes),
`/run/systemd/timesync/synchronized` (NTP), `/var/lib/update-notifier/updates-available` (atualizações) e os
certificados PEM, e envia a `POST /api/v1/agent/system-metrics`. Fonte ausente = sem amostra (nada de alerta falso).

**Certificados:** o agente roda sem privilégios e `/etc/letsencrypt/live` é 0700 do root. O `fullchain.pem` é
público, então copie-o para leitura do agente num hook de renovação:

```sh
# /etc/letsencrypt/renewal-hooks/deploy/sentinela
mkdir -p /etc/sentinela/certs
for d in /etc/letsencrypt/live/*/; do cp "$d/fullchain.pem" "/etc/sentinela/certs/$(basename "$d").pem"; done
chmod 644 /etc/sentinela/certs/*.pem
```

(O agente lê `/etc/sentinela/certs/*.pem` e, se tiver permissão, `/etc/letsencrypt/live/*/fullchain.pem`.)

## Registro de notificações (PostgreSQL)

Toda notificação — alerta disparado, alerta recuperado e **IP banido pelo fail2ban** — é gravada na tabela
`notifications` na mesma transação que a origina, com ou sem canal externo e mesmo que a entrega falhe. Os bans
valem P3/`warning`. Consulta: `GET /api/v1/notifications` (filtros `kind`, `priority`, `server_id`, `unread`,
`from`, `to`; `meta.unread` traz o total de não lidas); `POST /notifications/{id}/read` e `/notifications/read-all`
marcam como lidas. A fila de envio ao Telegram (`notification_outbox`) é separada e continua com retentativas.
## Incidentes

- Um incidente **aberto** por (servidor, regra, serviço): falha contínua não duplica incidentes nem notificações.
- Estados do alerta: `firing` → `acknowledged` (por um operador) → `resolved`; o incidente fecha junto.
- `priority` do incidente é herdada da regra; `recurrence_count` conta incidentes iguais resolvidos nas
  24 h anteriores. Se for > 0, a linha do tempo ganha o evento `recurrent` e o Telegram mostra "(reincidente: N× em 24 h)".
- Ao normalizar, uma mensagem de recuperação é enviada aos canais que receberam o aviso.

## Ainda não coberto (o agente não coleta esses dados)

Erros de leitura/escrita de disco (exigem `dmesg`/SMART), HTTP 5xx e health check de endpoints, tentativas de
login SSH (os logs do fail2ban já vão ao ClickHouse; os bans já notificam), mudanças em sudo/UFW/arquivos
críticos, métricas de PostgreSQL/Redis/goroutines e backup. Cada um precisa primeiro de um coletor no agente;
depois basta acrescentar uma entrada no catálogo. NTP só funciona com `systemd-timesyncd` (não com chrony) e as
atualizações só em Debian/Ubuntu com `update-notifier`.
