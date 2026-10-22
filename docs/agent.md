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

## Verificação de serviços locais (Fase 4)
O agente recebe em `GET /agent/config` a lista de serviços `tcp`/`systemd` do **seu** servidor (apenas id, nome, tipo, alvo e tempos) e envia os resultados em lote a `POST /agent/services`, no intervalo de cada serviço. A lista é atualizada a cada 60 s (ou na hora, se a API recusar algum resultado).

Segurança: a API diz *qual* serviço verificar; o agente decide *como*, com código próprio, e **revalida** cada alvo — `tcp` só conecta em loopback e `systemd` só aceita nomes `[A-Za-z0-9:_.@-]`, consultando o cgroup em vez de executar `systemctl`. Mesmo uma API comprometida não consegue fazer o agente conectar em outro host ou executar um comando.

## Envio de logs (nginx, fail2ban, ufw)
Opcional e desativado por padrão: `SENTINELA_LOGS=nginx,fail2ban,ufw`. O agente só **lê** os arquivos de log e confirma cada lote com a API antes de avançar a posição. Variáveis, formato e garantias em [logs.md](logs.md).
