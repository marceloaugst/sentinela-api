# Implantação em VPS Ubuntu (Docker Compose + Nginx + HTTPS)

Guia para Ubuntu 22.04/24.04. Arquitetura: **Nginx** (HTTPS, porta 443) → **API** (`127.0.0.1:8080`) → **PostgreSQL** (rede interna do Docker, sem porta publicada). Os agentes nos servidores monitorados falam HTTPS com a API.

```
Internet ─443─► Nginx ─127.0.0.1:8080─► sentinela-api ─rede interna─► postgres
                  │                         ▲
                  └─ SPA estática           └── agentes (HTTPS + token)
```

## 0. Atalho: script `deploy/setup-server.sh`
Para um servidor já com Docker e Nginx, e **sem domínio** (acesso por IP com HTTPS autoassinado), o script faz tudo: backup verificado e remoção do `server-monitor`, instalação em `/opt/sentinela`, Nginx em `https://<IP>/`, primeiro administrador.
```bash
./deploy/setup-server.sh --dry-run --admin-email voce@exemplo.com     # só mostra o plano (sem root)
./deploy/setup-server.sh --app-only --yes --admin-email voce@exemplo.com  # ensaio: só 127.0.0.1, nada removido
sudo ./deploy/setup-server.sh --admin-email voce@exemplo.com          # de verdade (pede para digitar REMOVER)
```
Opções: `--purge-data` (apaga também o banco `server_monitor` do Postgres compartilhado, após o dump), `--keep-server-monitor`, `--ip`, `--sm-source`, `--yes`. Se o Nginx não validar ou a API não responder, o site antigo é restaurado e **nada é removido**. É idempotente (o `.env` com os segredos nunca é regenerado). Os contêineres Postgres/Redis compartilhados nunca são derrubados. Com domínio, siga as seções abaixo (Let's Encrypt).

## 1. Pré-requisitos
- Domínio apontando (registro A/AAAA) para a VPS, ex.: `sentinela.exemplo.com`.
- Usuário não-root com `sudo`. Mínimo recomendado: 1 vCPU, 1 GB de RAM (Argon2id usa ~64 MiB por login simultâneo).

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install ca-certificates curl ufw nginx certbot python3-certbot-nginx
# Docker Engine + plugin compose: https://docs.docker.com/engine/install/ubuntu/
sudo usermod -aG docker "$USER" && newgrp docker
```

## 2. Firewall
```bash
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full'
sudo ufw enable
```
**Nunca** abra 8080 nem 5432. O compose já publica a API só em loopback e o PostgreSQL em nenhuma porta. (Portas publicadas pelo Docker ignoram o `ufw`; por isso o compose usa `127.0.0.1:` explicitamente — não remova.)

## 3. Código e configuração
```bash
sudo mkdir -p /opt/sentinela && sudo chown "$USER" /opt/sentinela
git clone <seu-repositorio> /opt/sentinela && cd /opt/sentinela
cp .env.example .env && chmod 600 .env
```
Edite o `.env` (gere os segredos; **não** os coloque no repositório):
```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
echo "SECRETS_KEY=$(openssl rand -hex 32)"
echo "METRICS_TOKEN=$(openssl rand -hex 24)"
```
Valores de produção:

| Variável | Valor |
|---|---|
| `APP_ENV` | `production` (liga `COOKIE_SECURE`, HSTS e exige Argon2id ≥ OWASP) |
| `TRUST_PROXY` | `true` (só porque o Nginx está na frente e a 8080 é loopback) |
| `CORS_ALLOWED_ORIGINS` | vazio se o frontend é do mesmo domínio; senão a origem exata (`https://painel.exemplo.com`) |
| `ADMIN_API_KEY` | **vazio** (a chave de automação fica desativada) |
| `SECRETS_KEY` | obrigatória para cadastrar tokens de bots; **guarde uma cópia fora do servidor** |
| `TELEGRAM_ALLOWED_CHAT_IDS` | seus chats/grupos autorizados |
| `METRICS_TOKEN` | token do Prometheus |

Frontend em **outro site** (não subdomínio do mesmo domínio): `COOKIE_SAMESITE=none` e `CORS_ALLOWED_ORIGINS` explícito (veja [security.md](security.md)).

## 4. Subir a aplicação
```bash
cd /opt/sentinela
docker compose -f deploy/compose.yaml --env-file .env up -d --build
docker compose -f deploy/compose.yaml --env-file .env logs -f api   # "migrações aplicadas" e "API iniciada"
curl -s http://127.0.0.1:8080/readyz
```
As migrações rodam na inicialização (`AUTO_MIGRATE=true`; seguro com várias instâncias: lock no banco).

### Primeiro administrador
Não existe cadastro público. Crie o primeiro admin **depois** do primeiro start (a senha vai pela entrada padrão, nunca por argumento):
```bash
read -r -s -p "Senha do admin: " PW; echo
printf '%s\n' "$PW" | docker compose -f deploy/compose.yaml --env-file .env run --rm -T api \
  create-admin --email voce@exemplo.com --name "Seu Nome"
unset PW
```
A senha precisa seguir a política (12–128 caracteres, não óbvia). Alternativa: definir `ADMIN_BOOTSTRAP_EMAIL`/`ADMIN_BOOTSTRAP_PASSWORD` no `.env` para o primeiro start e **remover a senha em seguida**. Recuperação: `… run --rm -T api reset-password --email voce@exemplo.com` (revoga as sessões).

## 5. Nginx e HTTPS
```bash
sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/sentinela
sudo sed -i 's/sentinela.exemplo.com/SEU.DOMINIO/g' /etc/nginx/sites-available/sentinela
# 1º, emita o certificado (o arquivo já referencia /etc/letsencrypt; use um server temporário na porta 80 se preciso):
sudo certbot certonly --nginx -d SEU.DOMINIO --agree-tos -m voce@exemplo.com
sudo ln -s /etc/nginx/sites-available/sentinela /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl list-timers | grep certbot      # renovação automática
```
O arquivo de exemplo já cobre: redirecionamento 80→443, TLS 1.2/1.3, HSTS, **SSE** (`proxy_buffering off`, leitura longa), limite de taxa no login e na API, `Host`/`X-Real-IP` corretos (necessários ao CSRF e ao bloqueio por IP) e `/metrics` restrito. O frontend (build estático) vai em `/var/www/sentinela`.

Teste: `curl -sI https://SEU.DOMINIO/healthz` → `200` com `strict-transport-security`; `curl -s -o /dev/null -w '%{http_code}\n' https://SEU.DOMINIO/metrics` → `403`.

## 6. Agentes nos servidores monitorados
1. No painel/API (como admin): cadastre o servidor e emita a credencial (`POST /api/v1/servers`, `POST /api/v1/servers/{id}/agent-credentials` — o token aparece **uma única vez**).
2. Compile o agente (`go build -o sentinela-agent ./cmd/agent`) e copie para o servidor.
3. No servidor monitorado:
   ```bash
   sudo ./deploy/install-agent.sh ./sentinela-agent https://SEU.DOMINIO -     # pede o token sem eco
   journalctl -u sentinela-agent -f
   ```
   O serviço roda sem privilégios (`DynamicUser`, `ProtectSystem=strict`, sem capabilities), com o token em arquivo `0600` entregue por `LoadCredential`.
4. Rotação: emita com `{"replace": true}`, grave o novo token em `/etc/sentinela/agent-token` e `systemctl restart sentinela-agent`.

## 7. Backup e restauração
```bash
sudo /opt/sentinela/deploy/backup.sh                    # teste manual
echo '17 3 * * * root /opt/sentinela/deploy/backup.sh >> /var/log/sentinela-backup.log 2>&1' | sudo tee /etc/cron.d/sentinela-backup
```
Gera `pg_dump -Fc` com rotação (14 dias) e valida o arquivo com `pg_restore --list`. **Copie para fora do servidor** (rclone/S3/rsync). O backup não contém a `SECRETS_KEY` — guarde-a à parte.

Restaurar (num banco vazio, com a API parada):
```bash
docker compose -f deploy/compose.yaml --env-file .env stop api
docker compose -f deploy/compose.yaml --env-file .env exec -T postgres \
  pg_restore -U sentinela -d sentinela --clean --if-exists --no-owner < /var/backups/sentinela/ARQUIVO.dump
docker compose -f deploy/compose.yaml --env-file .env start api
```
Os logs (ClickHouse, volume `chdata`) não fazem parte deste backup; veja [logs.md](logs.md#operação).

**Teste a restauração periodicamente** num ambiente descartável: backup que nunca foi restaurado não é backup.

## 8. Atualização e rollback
```bash
cd /opt/sentinela && sudo ./deploy/backup.sh && git pull
docker compose -f deploy/compose.yaml --env-file .env up -d --build     # migra e reinicia (clientes SSE reconectam sozinhos)
docker compose -f deploy/compose.yaml --env-file .env logs --tail 50 api
```
Rollback: volte o código (`git checkout <tag>`), rebuild; se uma migração precisar ser desfeita, `… run --rm api migrate-down` reverte **uma** por vez (faça backup antes). Em último caso, restaure o dump.

## 9. Operação
- **Saúde:** `/healthz` (processo), `/readyz` (PostgreSQL). Use `/readyz` em monitor externo de disponibilidade.
- **Prometheus:** alvo `https://SEU.DOMINIO/metrics` com `authorization: {credentials: <METRICS_TOKEN>}` e IP liberado no Nginx. Métricas úteis: `sentinela_http_requests_total{status="5xx"}`, `sentinela_job_duration_seconds{job,result}`, `sentinela_notifications_total{result="failed"}`, `sentinela_sse_clients`, `sentinela_agent_samples_total`, `sentinela_db_pool_*`.
- **Logs:** `docker compose … logs api` (JSON, com `request_id`, `user_id`, `actor`). Configure rotação do Docker (`/etc/docker/daemon.json`: `"log-driver":"local"` ou `json-file` com `max-size`).
- **Alertas sobre o próprio Sentinela:** monitore `auth.login_locked` na auditoria, mensagens com `status='failed'` em `notification_outbox` e a idade do último backup.
- **Recursos:** cada instância usa o pool (`DB_MAX_CONNS`, padrão 10) + 1 conexão do hub de eventos; ajuste `max_connections` do PostgreSQL se escalar.
- **Várias instâncias da API:** suportado (locks/leases no PostgreSQL; SSE por LISTEN/NOTIFY). O limite de taxa em memória passa a valer por instância.

## 10. Solução de problemas
| Sintoma | Causa provável |
|---|---|
| Login responde 200 mas a próxima requisição dá 401 | Cookie `Secure` sem HTTPS (acessando por `http://`), ou domínio/`SameSite` incompatíveis com o frontend. |
| 403 `CSRF_INVALID` em POST/PATCH/DELETE | Frontend não envia `X-CSRF-Token` (use o `csrf_token` do login/`/auth/me`). |
| 403 `ORIGIN_NOT_ALLOWED` | `Origin` fora de `CORS_ALLOWED_ORIGINS`, ou Nginx sem `proxy_set_header Host $host`. |
| 429 `LOGIN_LOCKED` | Excesso de tentativas; aguarde o `Retry-After` (≤ 15 min). Todos os usuários aparecem com o mesmo IP? Falta `TRUST_PROXY=true` + `X-Real-IP` no Nginx. |
| Stream de eventos cai a cada ~60 s | `proxy_read_timeout`/buffering do Nginx (use o bloco `/api/v1/events` do exemplo). |
| API não sobe: "em produção COOKIE_SECURE deve ser true" | Remova `COOKIE_SECURE=false` do `.env`. |
| `readyz` 503 | PostgreSQL indisponível: `docker compose … ps` / `logs postgres`. |
