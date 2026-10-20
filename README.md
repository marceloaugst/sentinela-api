# Sentinela

Monitoramento de servidores Linux: uma **API REST em Go** (PostgreSQL) que recebe métricas de um **agente** leve instalado em cada servidor, calcula alertas e incidentes e avisa por Telegram e em tempo real (SSE). O frontend é independente: qualquer SPA consome a API (veja o [guia para o frontend](docs/frontend-api.md)).

## Como funciona

```
 Servidores monitorados                         Servidor do Sentinela
┌─────────────────────┐   HTTPS + token    ┌───────────────────────────────────────────┐
│ sentinela-agent     │ ─────────────────► │ Nginx (443) ─► sentinela-api ─► PostgreSQL │
│ lê /proc (CPU, RAM, │   a cada 15 s      │                  │  ▲                      │
│ disco, rede, load)  │                    │   verificações   │  └─ jobs: alertas,      │
└─────────────────────┘                    │   HTTP centrais  │     retenção, notificações│
                                           └───────────────────┼─────────────────────────┘
        Navegador (seu frontend) ◄── API REST + SSE ───────────┘          │
        Telegram ◄──────────────── notificações de alertas ◄──────────────┘
```

1. **Agente** (`cmd/agent`): binário único, sem dependências. Só lê `/proc`, não abre portas e **nunca executa comandos** vindos da API. Envia heartbeat e métricas por HTTPS com um token individual (`snt_...`).
2. **API** (`cmd/api`): guarda métricas, calcula séries agregadas, avalia regras de alerta (com máquina de estados persistida), abre e fecha incidentes, faz verificações de serviço HTTP (com proteção anti-SSRF) e envia notificações.
3. **Tempo real**: `GET /api/v1/events` (SSE) com replay por `Last-Event-ID`, funcionando com várias instâncias da API sem broker externo.
4. **Acesso**: login por sessão (cookie `HttpOnly`), papéis `viewer < operator < admin`, proteção CSRF, bloqueio de força bruta, Argon2id e auditoria de ações.

Documentação detalhada: [arquitetura](docs/architecture.md) · [API](docs/api.md) · [guia para o frontend](docs/frontend-api.md) · [implantação](docs/deployment.md) · [agente](docs/agent.md) · [eventos](docs/events.md) · [segurança](docs/security.md) · [OpenAPI](api/openapi.yaml)

## Instalação

### Requisitos
- Linux com **Docker** e o plugin **docker compose**.
- Para publicar com HTTPS: **Nginx** (e um domínio, se quiser Let's Encrypt).
- Go 1.26+ só se for compilar ou desenvolver localmente.

### Opção A — um comando, em um servidor com IP (HTTPS autoassinado)
```bash
git clone https://github.com/SEU_USUARIO/sentinela.git
cd sentinela
./deploy/setup-server.sh --dry-run --admin-email voce@exemplo.com   # mostra o plano, não altera nada
sudo ./deploy/setup-server.sh --admin-email voce@exemplo.com
```
O script instala em `/opt/sentinela`, gera segredos aleatórios em `/opt/sentinela/.env` (modo 600), sobe API + PostgreSQL próprio em contêineres, publica a API em `https://<IP>/` pelo Nginx e cria o primeiro administrador (a senha é pedida sem eco).

> ⚠️ **Atenção:** esse script foi escrito para um servidor específico e **também remove uma instalação antiga chamada `server-monitor`**, se existir (com backup antes). Leia `deploy/setup-server.sh` e use `--dry-run` primeiro. Para só subir o Sentinela, sem publicar nem remover nada, use `--app-only`.

### Opção B — manual com Docker Compose (recomendada para domínio)
```bash
git clone https://github.com/SEU_USUARIO/sentinela.git /opt/sentinela && cd /opt/sentinela
cp .env.example .env && chmod 600 .env
```
Edite o `.env` (nunca o envie ao Git):
```bash
POSTGRES_PASSWORD=$(openssl rand -hex 24)
SECRETS_KEY=$(openssl rand -hex 32)      # cifra os tokens de bots; guarde uma cópia fora do servidor
METRICS_TOKEN=$(openssl rand -hex 24)
APP_ENV=production                        # exige HTTPS (cookie Secure)
TRUST_PROXY=true                          # somente atrás do Nginx
```
Suba e crie o primeiro administrador (a senha vai pela entrada padrão, nunca por argumento):
```bash
docker compose -f deploy/compose.yaml --env-file .env up -d --build
curl -s http://127.0.0.1:8080/readyz
read -r -s -p "Senha do admin (12+ caracteres): " PW; echo
printf '%s\n' "$PW" | docker compose -f deploy/compose.yaml --env-file .env run --rm -T api \
  create-admin --email voce@exemplo.com --name "Seu Nome"; unset PW
```
A API escuta só em `127.0.0.1:8080` e o PostgreSQL não publica porta. Coloque o Nginx na frente com [`deploy/nginx.conf.example`](deploy/nginx.conf.example) e emita o certificado com `certbot`. Passo a passo completo (firewall, HTTPS, backup, atualização): [docs/deployment.md](docs/deployment.md).

### Primeiro acesso
```bash
curl -sk -X POST https://SEU_SERVIDOR/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"voce@exemplo.com","password":"SUA_SENHA"}'
```
A resposta traz `csrf_token`; o cookie de sessão é definido automaticamente. Esqueceu a senha? `docker compose ... run --rm -T api reset-password --email voce@exemplo.com`.

### Instalar o agente em um servidor monitorado
1. Como `admin`, cadastre o servidor (`POST /api/v1/servers`) e emita a credencial (`POST /api/v1/servers/{id}/agent-credentials`). O token (`snt_...`) **aparece uma única vez**.
2. Compile o agente e copie para o servidor: `make build` gera `bin/sentinela-agent`.
3. No servidor monitorado:
   ```bash
   sudo ./deploy/install-agent.sh ./sentinela-agent https://SEU_SERVIDOR -    # pede o token sem eco
   journalctl -u sentinela-agent -f
   ```
Detalhes e o que é coletado: [docs/agent.md](docs/agent.md).

## Configuração
Tudo por variáveis de ambiente; a lista completa e comentada está em [`.env.example`](.env.example). As principais:

| Variável | Para quê |
|---|---|
| `APP_ENV` | `development`, `test` ou `production` (produção força cookie `Secure` e Argon2id forte) |
| `DATABASE_URL` / `POSTGRES_PASSWORD` | Conexão com o PostgreSQL (o compose monta a URL) |
| `SECRETS_KEY` | Chave AES-256 (hex, 64 caracteres) que cifra tokens de bots |
| `TRUST_PROXY` | `true` só atrás de proxy confiável que envia `X-Real-IP` |
| `CORS_ALLOWED_ORIGINS` | Origens permitidas quando o frontend está em outro host |
| `METRICS_TOKEN` | Token para `GET /metrics` (Prometheus) |
| `ADMIN_API_KEY` | Credencial de **automação** opcional; deixe vazia em produção |
| `METRICS_RETENTION_DAYS` | Quantos dias de métricas guardar (padrão 30) |

## Desenvolvimento
```bash
make build            # compila API e agente em bin/
make test             # testes unitários (-race)
make test-integration # testes com PostgreSQL efêmero via Docker
make up / make down   # sobe/derruba o compose local
```
Estrutura: `cmd/` (executáveis) · `internal/` (domínios: auth, servers, metrics, alerts, incidents, events…) · `migrations/` (SQL versionado, embutido no binário) · `api/openapi.yaml` · `deploy/` (Dockerfiles, compose, Nginx, scripts) · `docs/`.

Comandos da API: `sentinela-api migrate | migrate-down | create-admin | reset-password | version`.

## Segurança
- Segredos só em `.env` (ignorado pelo Git). **Nunca** publique o `.env`, dumps de banco ou chaves.
- Em produção use HTTPS sempre; sem ele o cookie de sessão não funciona.
- Limitações conhecidas: sem 2º fator, sem recuperação de senha por e-mail, limite de taxa em memória (por instância), rotação de `SECRETS_KEY` manual. Veja [docs/security.md](docs/security.md).

## Estado do projeto
Fases 1 a 6 concluídas: fundação, servidores e agente, métricas e dashboard, serviços/alertas/incidentes/Telegram, eventos em tempo real e autenticação com papéis e auditoria. O frontend não faz parte deste repositório.

## Licença
Ainda não definida. Antes de tornar o repositório público, adicione um arquivo `LICENSE` (por exemplo MIT).
