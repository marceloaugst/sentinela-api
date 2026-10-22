# Agente

Binário Go independente (`cmd/agent`), sem dependências externas além da biblioteca padrão. Somente lê `/proc`, `/etc/os-release` e `statfs`, e faz requisições de **saída** para a API. Não abre portas e **nunca executa comandos** recebidos da API; `GET /agent/config` só entrega números operacionais.

## Configuração (variáveis de ambiente)
| Variável | Descrição |
|---|---|
| `SENTINELA_API_URL` | Obrigatória. `https://...`; `http://` só para localhost (ou `SENTINELA_ALLOW_INSECURE_HTTP=true`) |
| `SENTINELA_AGENT_TOKEN` / `SENTINELA_AGENT_TOKEN_FILE` | Token emitido por `POST /servers/{id}/agent-credentials`. Prefira o arquivo (modo 0600) |
| `SENTINELA_INTERVAL_SECONDS` | Opcional (5–300). Sem ela, usa o valor da API (padrão 15 s) |

## Provisionamento
1. Logado como `admin`, `POST /api/v1/servers` → `id` (veja [frontend-api.md](frontend-api.md) para o login e o `X-CSRF-Token`).
2. `POST /api/v1/servers/{id}/agent-credentials` → guarde o `token` (**só aparece nesta resposta**).
3. No servidor monitorado: `SENTINELA_API_URL=... SENTINELA_AGENT_TOKEN_FILE=/etc/sentinela/token ./sentinela-agent`.
4. Rotação: emita com `{"replace": true}` (revoga as anteriores), atualize o arquivo e reinicie o agente.

## O que é coletado
| Item | Fonte | Definição |
|---|---|---|
| CPU % | `/proc/stat` | Δ(total − idle − iowait) / Δtotal entre coletas; `guest` não é somado em dobro |
| Load / uptime / CPUs | `/proc/loadavg`, `/proc/uptime`, `runtime.NumCPU` | |
| Memória | `/proc/meminfo` | **Usada = MemTotal − MemAvailable** (cache e buffers recuperáveis não contam como usados) |
| Swap | `/proc/meminfo` | total e `SwapTotal − SwapFree` |
| Rede | `/proc/net/dev` | Contadores **acumulados** somados; ignora `lo`, `docker*`, `veth*`, `br-*`, `virbr*`, `cni*`, `tun*`, `wg*` etc. A taxa é calculada no servidor por pares de amostras (`metrics.CalcRate`), descartando reset de contador e lacunas > 10 min |
| Discos | `/proc/mounts` + `statfs` | Só ext*/xfs/btrfs/zfs/f2fs/vfat/ntfs…; bind mounts e subvolumes do mesmo dispositivo são deduplicados (fica o caminho mais curto); máximo de 64 |
| Sistema | `/etc/os-release`, `os.Hostname`, `GOARCH` | |

## Descoberta automática de serviços
Sem cadastro: a cada minuto o agente procura no próprio host ssh, systemd-journald, cron, systemd-timesyncd, ufw, rsyslog, nginx, redis, docker e postgresql, e envia o retrato a `POST /agent/discovery` quando algo muda (ou a cada 5 min). A tela lê `GET /servers/{id}/discovery`.

| Como é achado | Fonte |
|---|---|
| Unidade em execução | cgroup `system.slice/<unidade>` (inclui instâncias como `postgresql@16-main`) |
| Instalado, mas parado | arquivo de unit em `/etc/systemd/system`, `/run/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system` |
| Processo no host | `/proc/<pid>/comm` |
| Ativação por socket (ex.: `ssh.socket`) | unit existe e a porta está em `LISTEN` em `/proc/net/tcp{,6}` |
| UFW | `ENABLED` em `/etc/ufw/ufw.conf` (o serviço é *oneshot*, sem processo) |
| **Redis/PostgreSQL em Docker** (quando não estão no host) | processo do serviço em cgroup `docker-*.scope`/`/docker/`, ou `docker-proxy` publicando a porta 6379/5432 (`-container-port` em `/proc/<pid>/cmdline`) |

O agente **não usa o socket do Docker** (dar acesso a ele equivale a root) e não executa comandos. Limite conhecido: um container de Redis/PostgreSQL **parado** não é visível sem o socket; aparece como `not_found`, e a dica já sugere o `docker run`. ### Ligação com os alertas
Cada serviço descoberto que **já foi visto disponível** vira um serviço monitorado do tipo `discovered` (nome "SSH (automático)", etc.). Se depois ele ficar `stopped` ou `not_found`, o serviço passa a `down`, e a regra `service_down` abre alerta, incidente e notificação (Telegram etc.). Detalhes:
- Quem **nunca existiu** no servidor (ex.: Redis não instalado) não gera alerta, só aparece como indisponível com o "o que fazer".
- A migração `0010` cria a regra global **"Serviço indisponível"** (`service_down`, crítica, 120 s para disparar, 60 s para recuperar) se ainda não houver nenhuma regra `service_down`. Ajuste ou desative em `/alert-rules`.
- Não há cadastro, edição nem exclusão de serviços pela API: a lista é sempre o que o agente encontra. Serviços cadastrados antes (`http`/`tcp`/`systemd`) foram arquivados pela migração `0011`.
- O agente não verifica mais URLs `http` nem portas `tcp` a pedido da API; `GET /agent/config` só devolve parâmetros operacionais.
- Servidor offline não gera alerta de serviço (só o de `server_offline`).

O texto "o que fazer" (`action`) é gerado pela API, nunca enviado pelo agente.

## Envio e resiliência
- Uma coleta por intervalo; o envio inteiro (com retentativas) fica limitado ao intervalo, então não há acúmulo de fila nem de memória (`GOMEMLIMIT` interno de 64 MiB).
- Falhas transitórias (rede, 408, 429, 5xx) → backoff exponencial com jitter (1 s, 2 s, 4 s… teto 30 s, até 4 tentativas); `Retry-After` é respeitado.
- Rejeições definitivas (401, 403, 422…) não são retentadas na mesma amostra; 401/403 são logadas como "credencial rejeitada" e o agente tenta de novo no próximo intervalo (o administrador pode reativar o servidor ou trocar o token).
- Amostras que não puderam ser enviadas são descartadas (sem fila offline). A API aceita `collected_at` até 1 h no passado, o que deixa espaço para evoluir isso.
- Encerra de forma limpa em SIGINT/SIGTERM.

## Unit systemd (exemplo)
```ini
[Service]
ExecStart=/usr/local/bin/sentinela-agent
Environment=SENTINELA_API_URL=https://sentinela.exemplo.com
Environment=SENTINELA_AGENT_TOKEN_FILE=/etc/sentinela/token
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
MemoryMax=96M
Restart=always
```
(`DynamicUser` precisa de `LoadCredential=` ou de um arquivo legível por esse usuário para o token.)

## Envio de logs (nginx, fail2ban, ufw)
Opcional e desativado por padrão: `SENTINELA_LOGS=nginx,fail2ban,ufw`. O agente só **lê** os arquivos de log e confirma cada lote com a API antes de avançar a posição. Variáveis, formato e garantias em [logs.md](logs.md).
