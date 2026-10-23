# Agente

Binário Go independente (`cmd/agent`), sem dependências externas além da biblioteca padrão. Somente lê `/proc`, `/etc/os-release` e `statfs`, e faz requisições de **saída** para a API. Não abre portas e **não executa comandos arbitrários**: a única coisa feita a pedido da API é iniciar/parar/reiniciar serviços do catálogo (seção abaixo); `GET /agent/config` só entrega números operacionais.

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

A descoberta dos serviços **não usa o socket do Docker**. Um container de Redis/PostgreSQL **parado** só é visível com o acesso opcional descrito em [Containers Docker](#containers-docker); sem ele aparece como `not_found`, e a dica sugere o `docker run`. Containers continuam fora dos botões de serviço (Iniciar/Parar/Reiniciar do `systemd`): eles têm tela própria.

### Iniciar, parar e reiniciar serviços
O painel (papel `operator` ou `admin`) pode pedir `start`, `stop` ou `restart` de um serviço descoberto (`POST /servers/{id}/services/{key}/actions`). O fluxo mantém o agente só com conexões de **saída**:
1. A API grava o pedido em `service_commands` (com quem pediu, e-mail e IP) e na auditoria (`service.start|stop|restart`).
2. A cada ~5 s o agente chama `GET /agent/commands` e recebe **só** `(id, service_key, action)` — nunca nome de unidade nem comando.
3. O agente resolve a unidade pela **própria** descoberta, confere com o catálogo (`ssh.socket` → `ssh.service`), confere se a ação é permitida para o estado atual e roda `systemctl --no-ask-password <ação> <unidade>` (sem shell, 60 s de limite).
4. Devolve o resultado em `POST /agent/commands/{id}/result` (auditoria `service.result`) e reenvia a descoberta, para a tela refletir o novo estado.

**Privilégio:** o agente continua como `DynamicUser`, sem capabilities. Quem autoriza é o **polkit**: `deploy/50-sentinela-agent.rules` (instalado em `/etc/polkit-1/rules.d/` por `install-agent.sh`, `setup-local-agent.sh` e `update.sh`) libera os verbos `start|stop|restart` **só** para o usuário `sentinela-agent` e **só** nas unidades do catálogo. `enable`, `mask`, `kill`, `daemon-reload` e qualquer outra unidade seguem negados. Requer o pacote `polkitd` (já vem no Ubuntu/Debian com systemd). Se a lista de unidades do catálogo mudar, atualize também a regra.

**Limites de segurança:** só unidades **systemd** (processo solto não; containers têm fluxo próprio, abaixo); o **SSH só pode ser iniciado/reiniciado** (parar trancaria o administrador fora); `journald` e `ufw` não têm ação; um comando por serviço por vez; pedido que o agente não busca em 2 min **expira**, e comando sem resultado em 5 min vira **falha**. Parar um serviço faz o alerta "Serviço indisponível" disparar depois de 120 s, como qualquer queda.

**Atenção ao parar o `nginx`/`docker` do próprio servidor da API:** o agente tenta enviar o resultado por até ~90 s; se a API ficar inacessível, o comando acaba marcado como falha por tempo esgotado mesmo tendo funcionado.

### Processos
A cada 30 s o agente lê `/proc` e envia o retrato a `POST /agent/processes` (os 150 que mais usam CPU, completados até 300 com os de maior memória; `total` diz quantos existem). A tela lê `GET /servers/{id}/processes`. Guia: [frontend-processos.md](frontend-processos.md).

- **CPU%** = diferença de `utime+stime` (`/proc/<pid>/stat`) entre duas leituras, em % de um núcleo (100 = um núcleo; máximo `100 × cpus`). Processo que apareceu depois da leitura anterior conta todo o tempo de CPU dele. A primeira leitura (ao iniciar) só serve de base.
- **Memória** = RSS (`/proc/<pid>/stat`). Páginas compartilhadas entre processos são contadas em cada um (a soma pode passar da RAM). Não usa PSS (`smaps_rollup`): ele só é legível para processos do mesmo usuário e é caro de ler.
- **`cmdline`** passa por uma máscara de segredos (`--password=…`, `TOKEN=…`, `user:senha@host`, argumento depois de `--password`). É heurística: não envie segredo em argumentos de linha de comando.
- **Servidor "quente":** se CPU ou memória estão em 85 % ou mais na coleta de métricas, o agente envia os processos a cada ~10 s (em vez de 30 s) para registrar quem consome durante o pico. Cada relatório alimenta o histórico no ClickHouse (5 maiores por CPU e por memória; `GET /servers/{id}/processes/history`) e os alertas de CPU/memória, que apontam os maiores consumidores.
- Cada processo vem com `restriction` (fato do agente; o texto é gerado pela API): `critical`, `self`, `container`, `service` (unidade systemd do catálogo, lida em `/proc/<pid>/cgroup`), `other_user` ou vazio.
- **Encerrar** (`terminate` = SIGTERM, `kill` = SIGKILL) é restrito a processos **do mesmo usuário do agente**, sem restrição. A API manda `(pid, início do processo, ação)`; o agente abre um **pidfd** (que prende o processo), confere em `/proc` que o início confere e que a restrição continua vazia, e só então sinaliza pelo pidfd, de modo que um pid reaproveitado nunca é atingido. Espera até 5 s (SIGTERM) ou 3 s (SIGKILL) e informa se o processo saiu. Como o agente padrão roda como usuário dinâmico (`DynamicUser=yes`) e não é root, **na instalação padrão quase todo processo é `other_user`** e o botão não aparece; ele passa a valer se o agente rodar como o usuário dos processos que se quer encerrar. Não há acréscimo de privilégio nem regra polkit para isso.

### Containers Docker
A cada minuto o agente verifica o Docker do host e envia o retrato a `POST /agent/docker` (quando algo muda, ou a cada 5 min). A tela lê `GET /servers/{id}/docker`.

| `status` | Significado |
|---|---|
| `ok` | Docker acessível; a lista de containers vem em `containers` |
| `not_installed` | não há socket do Docker (`/var/run/docker.sock`); o agente reavalia a cada minuto |
| `no_access` | o Docker existe, mas o agente não tem permissão no socket (acesso não habilitado) |
| `unavailable` | o socket existe, mas o daemon não responde (parado) |
| `unknown` | só na API: o agente ainda não enviou nada |

- **Ativo** (`running`/`restarting`): ação **Reiniciar**. **Inativo** (`exited`/`created`/`dead`): ação **Iniciar**. Pausado e em remoção: nenhuma.
- **Inativo** também traz `error` (por que parou: erro do Docker, falta de memória, código de saída, sinal) e `log_tail` (últimas 15 linhas do log, até 2000 caracteres).
- O pedido usa o mesmo caminho dos comandos de serviço (`service_commands`, `target` = id completo do container): `POST /servers/{id}/docker/containers/{id}/actions` → o agente busca em até ~5 s, confere o id e o estado contra a **própria** listagem e chama `POST /containers/{id}/start|restart` no socket. Depois de 3 s ele confere se o container ficou ativo; se não, o comando termina em `failed` com o motivo.
- O agente só faz estas chamadas ao daemon: `GET /version`, `/containers/json`, `/containers/{id}/json`, `/containers/{id}/logs`, `POST /containers/{id}/start` e `/restart`. Não há `exec`, `create`, `rm`, `kill`, volumes nem imagens.

**Habilitar o acesso (opcional, desligado por padrão):**

```bash
sudo ./deploy/update.sh --docker     # servidor já instalado
sudo ./deploy/install-agent.sh BIN URL TOKEN --docker   # instalação nova
AGENT_DOCKER=yes ./deploy/setup-local-agent.sh          # esta máquina
sudo ./deploy/update.sh --no-docker  # remove o acesso
```

Isso cria o drop-in `/etc/systemd/system/sentinela-agent.service.d/docker.conf` com `SupplementaryGroups=docker`. **Atenção:** quem fala com o socket do Docker consegue virar root no servidor (por exemplo, criando um container privilegiado). O agente só usa as chamadas acima e só obedece a `(id, ação)` conferidos, mas um bug no agente, ou a captura do processo, passaria a valer como root. Habilite só se aceitar esse risco. Outro socket: `SENTINELA_DOCKER_SOCKET` no unit.

O `log_tail` é o texto cru do container e pode conter dados sensíveis da aplicação; ele é gravado no PostgreSQL e visível a todos os papéis (`viewer` inclusive).

### Ligação com os alertas
Cada serviço descoberto que **já foi visto disponível** vira um serviço monitorado do tipo `discovered` (nome "SSH (automático)", etc.). Se depois ele ficar `stopped` ou `not_found`, o serviço passa a `down`, e a regra `service_down` abre alerta, incidente e notificação (Telegram etc.). Detalhes:
- Quem **nunca existiu** no servidor (ex.: Redis não instalado) não gera alerta, só aparece como indisponível com o "o que fazer".
- A regra automática **"Serviço indisponível"** (`service_down`, P1, 120 s para disparar, 60 s para recuperar) faz parte do catálogo fixo (veja `docs/alertas-automaticos.md`) e não é editável.
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
