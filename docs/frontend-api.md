# Sentinela — Guia da API para o frontend

> Gerado a partir de `api/openapi.yaml` (fonte da verdade, v0.6.0). Se a API mudar, regenere ou consulte o OpenAPI.

**URL base:** `https://SEU_SERVIDOR/api/v1` (IP ou domínio onde você instalou o Sentinela).
Verificação de saúde: `https://SEU_SERVIDOR/healthz` e `/readyz` (fora de `/api/v1`).

Se você instalou com `deploy/setup-server.sh` (acesso por IP), o certificado é **autoassinado**. No navegador é preciso aceitá-lo uma vez (abra `https://SEU_SERVIDOR/` e confirme a exceção) ou importar `/etc/sentinela/tls/server.crt` como autoridade confiável. Com um domínio e Let's Encrypt isso desaparece.

## 1. Como o frontend deve falar com a API

### Mesma origem é o caminho mais simples
A autenticação é por **cookie de sessão `HttpOnly`** (`__Host-sentinela_session`, `Secure`, `SameSite=Lax`). Cookie `SameSite=Lax` não vai em requisições entre sites diferentes, então o frontend deve ser servido **no mesmo host** que a API, ou acessar a API por proxy.

- **Desenvolvimento (Vite):** use proxy para ficar na mesma origem.
  ```js
  // vite.config.js
  export default { server: { proxy: { '/api': { target: 'https://SEU_SERVIDOR', secure: false, changeOrigin: false } } } }
  ```
  No código use sempre caminhos relativos: `fetch('/api/v1/...')`. Com `changeOrigin: false` o cabeçalho `Host` não é reescrito. A API compara o `Origin` do navegador com o `Host`, então o frontend e a API precisam parecer a mesma origem (`http://localhost:5173`). Se a API recusar com `ORIGIN_NOT_ALLOWED`, adicione `CORS_ALLOWED_ORIGINS=http://localhost:5173` no `/opt/sentinela/.env` e reinicie a API. Em HTTP puro o cookie `Secure` pode não ser guardado por alguns navegadores; `localhost` é tratado como seguro por Chrome e Firefox.
- **Produção:** sirva o build estático pelo próprio Nginx do servidor (por exemplo em `/`) e a API continua em `/api/`.
- **Frontend em outro domínio:** exige `COOKIE_SAMESITE=none` e `CORS_ALLOWED_ORIGINS=https://seu-front` no `.env`, e `credentials: 'include'` em todo `fetch`.

### Fluxo de login
1. `POST /api/v1/auth/login` com `{"email","password"}`. A resposta define o cookie e traz `data.csrf_token`.
2. Guarde o `csrf_token` **em memória** (não em `localStorage`).
3. Em **toda** requisição `POST`, `PATCH` ou `DELETE` envie o cabeçalho `X-CSRF-Token: <csrf_token>`. Sem ele: `403 CSRF_INVALID`.
4. Ao recarregar a página, chame `GET /api/v1/auth/me`: se houver sessão, devolve o usuário e um `csrf_token` novo; se não, `401`.
5. `POST /api/v1/auth/logout` encerra a sessão.

```js
let csrf = null;

export async function api(path, { method = 'GET', body, query } = {}) {
  const url = new URL('/api/v1' + path, location.origin);
  if (query) Object.entries(query).forEach(([k, v]) => v != null && url.searchParams.set(k, v));
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  const res = await fetch(url, { method, headers, credentials: 'same-origin',
                                 body: body !== undefined ? JSON.stringify(body) : undefined });
  if (res.status === 204) return null;
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(json.error?.message ?? res.statusText),
                                   { status: res.status, code: json.error?.code, details: json.error?.details });
  return json;                      // { data, meta? }
}

export async function login(email, password) {
  const r = await api('/auth/login', { method: 'POST', body: { email, password } });
  csrf = r.data.csrf_token; return r.data.user;
}
export async function restoreSession() {
  try { const r = await api('/auth/me'); csrf = r.data.csrf_token; return r.data.user; }
  catch (e) { if (e.status === 401) return null; throw e; }
}
```

### Tempo real (SSE)
`GET /api/v1/events` funciona com o `EventSource` nativo, que envia o cookie sozinho e se reconecta reenviando `Last-Event-ID`:
```js
const es = new EventSource('/api/v1/events?types=alert.triggered,alert.resolved,server.status_changed,incident.created', { withCredentials: true });
es.addEventListener('alert.triggered', (e) => { const ev = JSON.parse(e.data); /* ev.data.* */ });
es.addEventListener('resync', () => { /* recarregue o estado pela API */ });
```
Tipos: `server.status_changed`, `metrics.updated` (opt-in, no máximo 1 a cada 5 s por servidor), `alert.triggered|acknowledged|resolved`, `incident.created|resolved`, `service.status_changed`, `resync`. Filtro por servidor: `?server_id=<uuid>`. Limite de 20 conexões por IP.

## 2. Formato das respostas

| Situação | Corpo |
|---|---|
| Sucesso | `{"data": ..., "meta": {...}}` (`meta` só em listas paginadas) |
| Sem conteúdo | `204`, corpo vazio |
| Erro | `{"error": {"code": "VALIDATION_ERROR", "message": "...", "details": [{"field": "name", "message": "..."}]}}` |

**Paginação:** parâmetros `page` (≥ 1, padrão 1) e `per_page` (1–100, padrão 20); `meta` traz `page`, `per_page`, `total`, `total_pages`.

**Códigos de erro comuns:** `401` sem sessão/expirada · `403` papel insuficiente (`FORBIDDEN`), `CSRF_INVALID`, `ORIGIN_NOT_ALLOWED` · `404` · `409` conflito · `413` corpo grande · `422` validação (use `details[].field` para marcar o campo no formulário) · `429` `LOGIN_LOCKED`/`RATE_LIMITED` (veja o cabeçalho `Retry-After`).

**Papéis:** `viewer` (só leitura) < `operator` (reconhece/resolve alertas, executa verificações) < `admin` (tudo, inclusive usuários, servidores, credenciais e canais). Use `GET /auth/me` → `user.role` para esconder o que o usuário não pode fazer; a API é quem garante.

**Datas** em ISO-8601 UTC (`2026-10-20T18:00:00Z`). **IDs** são UUIDs, exceto `id` de eventos SSE (inteiro).

**Limites de login:** 5 falhas do mesmo e-mail e IP, 20 falhas de um IP ou 30 falhas do mesmo e-mail em 15 minutos bloqueiam por um tempo (`429 LOGIN_LOCKED`). Mostre o `Retry-After` ao usuário.

## 3. Mapa rápido por tela

| Tela | Endpoints |
|---|---|
| Login / sessão | `POST /auth/login`, `GET /auth/me`, `POST /auth/logout`, `POST /auth/logout-all`, `POST /auth/change-password` |
| Dashboard | `GET /dashboard/summary`, `/dashboard/metrics`, `/dashboard/recent-alerts`, `/dashboard/recent-incidents` + SSE |
| Lista de servidores | `GET /servers` (filtros `q`, `status`, `connection`, `sort`, `order`) |
| Detalhe do servidor | `GET /servers/{id}`, `/servers/{id}/summary`, `/servers/{id}/metrics`, `/servers/{id}/disks`, `/servers/{id}/services`, `/servers/{id}/discovery`, `/servers/{id}/incidents` |
| Cadastro / credencial do agente | `POST /servers`, `PATCH /servers/{id}`, `POST /servers/{id}/agent-credentials` (o token aparece **uma única vez**) |
| Serviços (descobertos automaticamente, somente leitura) | `GET /services`, `GET /services/{id}` |
| Alertas e regras | `GET /alerts`, `POST /alerts/{id}/acknowledge`, `POST /alerts/{id}/resolve`, `GET /alert-rules`, `GET /alert-rules/{id}` (somente leitura: as regras são automáticas) |
| Incidentes | `GET /incidents`, `GET /incidents/{id}`, `GET /incidents/{id}/events` |
| Notificações (Telegram) | `GET/POST /notification-channels`, `PATCH/DELETE /notification-channels/{id}`, `POST /notification-channels/{id}/test` |
| Administração | `GET/POST /users`, `PATCH /users/{id}`, `POST /users/{id}/sessions/revoke`, `GET /audit-logs` |

Os endpoints de **agente** (`/agent/*`) são usados pelo programa instalado nos servidores monitorados (token `snt_...`), não pelo navegador.

---

# Referência de endpoints

Base: `{BASE}/api/v1` (exceto onde indicado). Papel mínimo: `viewer` < `operator` < `admin`.

## Autenticação

### `POST /api/v1/auth/login`
**Login (cria a sessão)** — pública

Valida e-mail e senha e cria uma **sessão** (cookie `HttpOnly`). A resposta traz o `csrf_token` que o frontend deve enviar
no cabeçalho `X-CSRF-Token` em toda requisição que altera estado (POST/PATCH/DELETE).

Toda falha de credencial (senha errada, e-mail inexistente, conta desativada) devolve a **mesma** resposta `401 INVALID_CREDENTIALS`
e leva o mesmo tempo (sem enumeração de contas). **Bloqueio** (429 `LOGIN_LOCKED`, com `Retry-After`): 5 falhas do mesmo e-mail a partir do
mesmo IP, 20 falhas de um IP, ou 30 falhas do mesmo e-mail em IPs diferentes, dentro de 15 min; o bloqueio é checado **antes** da senha e se
desfaz sozinho. Um atacante em outro IP não consegue trancar o usuário legítimo. Endpoint com limite de taxa próprio (429 `RATE_LIMITED`).

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `email` | string(email) | sim |  |
| `password` | string | sim |  |

**Respostas**

- `200` — Autenticado. Define o cookie de sessão.

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | SessionInfo |  |  |

- `401` — Credenciais inválidas (INVALID_CREDENTIALS)
- `413` — Corpo acima de 8 KiB
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — LOGIN_LOCKED (tentativas demais) ou RATE_LIMITED; veja Retry-After

### `POST /api/v1/auth/logout`
**Encerra a sessão atual** — papel mínimo: **viewer**

**Respostas**

- `204` — Sessão revogada e cookie removido
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/auth/logout-all`
**Encerra todas as sessões do usuário (todos os dispositivos)** — papel mínimo: **viewer**

**Respostas**

- `204` — Todas as sessões revogadas
- `400` — Chamado com a chave de API (não há sessão)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/auth/me`
**Usuário autenticado e token CSRF** — papel mínimo: **viewer**

Reemite o `csrf_token` (derivado da sessão), útil após recarregar a página. Com a chave de API devolve `via` igual a `api_key` e nenhum token CSRF.

**Respostas**

- `200` — Sessão atual

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | SessionInfo |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/auth/change-password`
**Troca a própria senha** — papel mínimo: **viewer**

Exige a senha atual (cada erro conta para o bloqueio de login). Aplica a política de senhas (12–128 caracteres, sem senhas comuns, sem
conter e-mail ou nome). **Revoga todas as sessões** e devolve uma sessão nova para este dispositivo (novo cookie e novo `csrf_token`).

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `current_password` | string | sim |  |
| `new_password` | string | sim |  |

**Respostas**

- `200` — Senha trocada; cookie rotacionado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object |  |  |
| `data.csrf_token` | string |  |  |
| `data.expires_at` | string(date-time) |  |  |
| `data.idle_expires_at` | string(date-time) |  |  |

- `400` — Chamado com a chave de API (NOT_A_SESSION)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — LOGIN_LOCKED

## Usuários e auditoria

### `GET /api/v1/users`
**Lista usuários** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `q` | query | string |  | Busca por nome ou e-mail |
| `role` | query | UserRole |  |  |
| `is_active` | query | boolean |  |  |

**Respostas**

- `200` — Página de usuários

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | User[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/users`
**Cria um usuário** — papel mínimo: **admin**

Não há cadastro público. A senha segue a política (12–128 caracteres...) e é guardada com Argon2id; nunca é devolvida.

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string | sim |  |
| `email` | string(email) | sim |  |
| `role` | UserRole | sim |  |
| `password` | string | sim |  |

**Respostas**

- `201` — Criado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | User |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `409` — Nome já em uso (CONFLICT)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/users/{id}`
**Detalhe do usuário** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Usuário

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | User |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `PATCH /api/v1/users/{id}`
**Altera nome, e-mail, papel, estado ou redefine a senha** — papel mínimo: **admin**

Desativar (`is_active: false`) ou redefinir a senha **revoga todas as sessões** do usuário imediatamente (`meta.revoked_sessions`).
Mudanças de papel valem na próxima requisição. O **último administrador ativo** não pode ser desativado nem rebaixado (409 `LAST_ADMIN`).

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string |  |  |
| `email` | string(email) |  |  |
| `role` | UserRole |  |  |
| `is_active` | boolean |  |  |
| `password` | string |  |  |

**Respostas**

- `200` — Usuário atualizado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | User |  |  |
| `meta` | object |  |  |
| `meta.revoked_sessions` | integer |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `409` — E-mail em uso (CONFLICT) ou último administrador (LAST_ADMIN)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/users/{id}/sessions/revoke`
**Revoga todas as sessões de um usuário** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Sessões revogadas

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object |  |  |
| `data.revoked_sessions` | integer |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/audit-logs`
**Trilha de auditoria (mais recentes primeiro)** — papel mínimo: **admin**

Registra quem fez o quê: login, usuários, servidores, credenciais de agente, serviços, regras, canais, reconhecimento/resolução de alertas.
**Nunca** contém senhas, hashes, tokens de sessão/CSRF/agente nem tokens de bots. Retenção: `AUDIT_RETENTION_DAYS` (365).

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `action` | query | string |  | Igualdade, ou prefixo quando termina com '.' (ex.: `user.`) |
| `resource_type` | query | string |  |  |
| `resource_id` | query | string |  |  |
| `actor_user_id` | query | string(uuid) |  |  |
| `from` | query | string(date-time) |  |  |
| `to` | query | string(date-time) |  |  |

**Respostas**

- `200` — Página de registros

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | AuditEntry[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Servidores

### `GET /api/v1/servers`
**Lista servidores** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `q` | query | string |  | Busca por nome ou hostname (parcial |
| `status` | query | AdminStatus |  |  |
| `connection` | query | ConnectionStatus |  |  |
| `sort` | query | `name` \| `hostname` \| `status` \| `created_at` \| `last_seen_at` padrão name |  |  |
| `order` | query | `asc` \| `desc` padrão asc |  |  |

**Respostas**

- `200` — Página de servidores

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Server[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/servers`
**Cadastra um servidor** — papel mínimo: **admin**

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string | sim |  |
| `hostname` | string | sim | Nome de host ou IP |

**Respostas**

- `201` — Criado (cabeçalho Location aponta para o recurso)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Server | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `409` — Nome já em uso (CONFLICT)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/servers/{id}`
**Detalhe do servidor** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Servidor

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Server | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `PATCH /api/v1/servers/{id}`
**Atualiza nome, hostname ou estado administrativo** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string |  |  |
| `hostname` | string |  |  |
| `status` | AdminStatus |  |  |

**Respostas**

- `200` — Servidor atualizado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Server | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `409` — Nome já em uso (CONFLICT)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `DELETE /api/v1/servers/{id}`
**Remove o servidor (exclusão lógica)** — papel mínimo: **admin**

O histórico (métricas, alertas, incidentes) é preservado, as credenciais do agente são
revogadas e o nome fica disponível para reutilização.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `204` — Removido
- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/servers/{id}/disks`
**Volumes do servidor (última coleta, um por ponto de montagem)** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Volumes

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Disk[] | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Credenciais de agente

### `GET /api/v1/servers/{id}/agent-credentials`
**Lista credenciais do servidor (sem token)** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Credenciais

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Credential[] | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/servers/{id}/agent-credentials`
**Emite uma credencial de agente** — papel mínimo: **admin**

O token completo é devolvido **apenas nesta resposta** (`Cache-Control: no-store`);
o banco guarda somente o hash SHA-256. Com `replace=true` as credenciais ativas
anteriores são revogadas na mesma transação.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `expires_in_days` | integer |  | Sem valor = não expira |
| `replace` | boolean |  |  |

**Respostas**

- `201` — Credencial emitida

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | IssuedCredential | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `DELETE /api/v1/servers/{id}/agent-credentials/{credentialId}`
**Revoga uma credencial** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |
| `credentialId` | path | string(uuid) | sim |  |

**Respostas**

- `204` — Revogada
- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Métricas

### `GET /api/v1/servers/{id}/summary`
**Resumo do servidor (última amostra, discos, alertas, serviços, disponibilidade)** — papel mínimo: **viewer**

`latest.network` é a taxa entre as duas últimas amostras e fica nula quando o par não é
confiável (reset de contador, lacuna > 10 min ou sem dados). `availability` considera a janela
de 24 h (ou desde o cadastro, se mais recente): cada amostra mantém o servidor online por até
`AGENT_HEARTBEAT_TIMEOUT_SECONDS`, usando o horário de recebimento. `percent` é nulo se a janela tiver menos de 1 minuto.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Resumo

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | ServerSummary |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/servers/{id}/metrics`
**Histórico de métricas do servidor** — papel mínimo: **viewer**

Período `[from, to)`; padrão: última hora. Sem `interval`, usa amostras originais (`raw`) para
períodos de até 1 h e, acima disso, o menor balde que mantém no máximo 1000 pontos. Máximo de 90 dias.
Cada métrica traz `min/avg/max` (em `raw` os três são iguais). Baldes sem amostras são omitidos.
Taxas de rede são calculadas entre amostras consecutivas e descartam resets de contador e lacunas > 10 min.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |
| `from` | query | string(date-time) |  |  |
| `to` | query | string(date-time) |  |  |
| `interval` | query | `raw` \| `1m` \| `5m` \| `15m` \| `1h` \| `6h` \| `1d` |  |  |

**Respostas**

- `200` — Série temporal

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | MetricPoint[] | sim |  |
| `meta` | SeriesMeta | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Dashboard

### `GET /api/v1/dashboard/summary`
**Resumo agregado do painel** — papel mínimo: **viewer**

Recursos consideram apenas servidores **online**, usando a última amostra de cada um.
Memória e disco: Σ usado / Σ total (nunca média simples de percentuais). CPU: média ponderada pelo
número de CPUs lógicas, máximo e distribuição (low < 50%, medium 50–80%, high ≥ 80%).
Alertas e incidentes de servidores removidos não contam.

**Respostas**

- `200` — Resumo

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | DashboardSummary |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/dashboard/metrics`
**Série agregada de vários servidores** — papel mínimo: **viewer**

Mesmas regras de período de `/servers/{id}/metrics`, exceto que `raw` não é aceito (mínimo 1m).
Memória do balde = Σ usado / Σ total das amostras do balde.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `from` | query | string(date-time) |  |  |
| `to` | query | string(date-time) |  |  |
| `interval` | query | `1m` \| `5m` \| `15m` \| `1h` \| `6h` \| `1d` |  |  |
| `server_id` | query | string(uuid)[] |  | Restringe a servidores (UUIDs; repetido ou separado por vírgula; máx. 50). Omitido = todos. |

**Respostas**

- `200` — Série agregada

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | AggregatedPoint[] | sim |  |
| `meta` | SeriesMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/dashboard/recent-alerts`
**Alertas recentes (mais novos primeiro)** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `limit` | query | integer padrão 10 máx 50 |  |  |
| `status` | query | `active` \| `pending` \| `firing` \| `acknowledged` \| `resolved` |  | `active` = não resolvidos |

**Respostas**

- `200` — Alertas

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | RecentAlert[] |  |  |
| `meta` | object |  |  |
| `meta.limit` | integer |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/dashboard/recent-incidents`
**Incidentes recentes (mais novos primeiro)** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `limit` | query | integer padrão 10 máx 50 |  |  |
| `status` | query | `open` \| `resolved` |  |  |

**Respostas**

- `200` — Incidentes (`duration_seconds` de incidente aberto é o tempo decorrido até agora)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | RecentIncident[] |  |  |
| `meta` | object |  |  |
| `meta.limit` | integer |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Serviços (descoberta automática)

### `GET /api/v1/servers/{id}/discovery`
**Serviços do sistema descobertos automaticamente** — papel mínimo: **viewer**

Nada precisa ser cadastrado: o agente procura sozinho `ssh`, `journald`, `cron`, `timesyncd`, `ufw`, `rsyslog`, `nginx`, `redis`, `docker` e `postgresql`. Redis e PostgreSQL, se não estiverem no host, são procurados em containers Docker. Sem relatório do agente ainda, `services` vem vazio e `checked_at` nulo (mostre "aguardando o agente").

**Respostas**

- `200` — `data`:

| Campo | Tipo | Descrição |
|---|---|---|
| `summary` | `{total, available, unavailable}` | Contagens, para o cabeçalho do painel |
| `checked_at` | string(date-time) \| null | Último relatório do agente |
| `services[]` | DiscoveryItem | Na ordem do catálogo |

`DiscoveryItem`:

| Campo | Tipo | Descrição |
|---|---|---|
| `key` | string | `ssh`, `journald`, `cron`, `timesyncd`, `ufw`, `rsyslog`, `nginx`, `redis`, `docker`, `postgresql` |
| `name` | string | Nome para exibir |
| `available` | boolean | `true` = em execução |
| `status` | string | `available` (em execução), `stopped` (instalado, mas parado/desativado), `not_found` (não instalado) |
| `source` | string | Onde foi achado: `systemd`, `process` (processo no host) ou `docker` (container); vazio se não disponível |
| `unit` | string | Unidade systemd, quando houver |
| `action` | string | **O que fazer para ficar disponível** (comandos Debian/Ubuntu); vazio quando já está disponível |
| `checked_at` / `status_changed_at` | string(date-time) | Última verificação / última mudança de `status` |

**Alertas:** serviços que já estiveram disponíveis aparecem também em `GET /services` com `service_type: "discovered"` (nome "… (automático)"), e a queda deles gera alerta/incidente pela regra `service_down` (a migração cria a regra padrão "Serviço indisponível"). Quem nunca esteve disponível não alerta.

Sugestão de tela: cartão verde para `available` (mostrando `source`) e cartão vermelho/âmbar para os demais, com `action` em um bloco de código copiável.

### `GET /api/v1/servers/{id}/services`
**Serviços do servidor** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Página de serviços

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Service[] | sim |  |
| `meta` | PageMeta | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/services`
**Lista serviços monitorados** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `q` | query | string |  | Busca por nome ou alvo |
| `server_id` | query | string(uuid) |  |  |
| `status` | query | `up` \| `down` \| `degraded` \| `unknown` |  |  |
| `service_type` | query | `discovered` |  |  |

**Respostas**

- `200` — Página de serviços

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Service[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/services/{id}`
**Detalhe do serviço** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Serviço

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Service |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/alert-rules`
**Lista as regras automáticas de alerta (somente leitura)** — papel mínimo: **viewer**

As regras vêm de um catálogo fixo (CPU, RAM, swap, load, disco, servidor sem comunicação, serviço indisponível)
sincronizado com o PostgreSQL a cada inicialização da API. Não há cadastro, edição nem exclusão pela API.
Ordenadas por prioridade (P1 primeiro).

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `metric_name` | query | MetricName |  |  |
| `severity` | query | Severity |  |  |
| `priority` | query | `1` \| `2` \| `3` \| `4` |  |  |
| `enabled` | query | boolean |  |  |

**Respostas**

- `200` — Página de regras

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | AlertRule[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/alert-rules/{id}`
**Detalhe da regra** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Regra

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | AlertRule |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/alerts`
**Lista alertas (mais recentes primeiro)** — papel mínimo: **viewer**

Alertas `pending` (condição verdadeira, ainda dentro de `duration_seconds`) ainda não são alertas e não aparecem.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `status` | query | `active` \| `firing` \| `acknowledged` \| `resolved` |  | `active` = firing + acknowledged |
| `severity` | query | Severity |  |  |
| `server_id` | query | string(uuid) |  |  |
| `rule_id` | query | string(uuid) |  |  |
| `from` | query | string(date-time) |  | Início (triggered_at >=) |
| `to` | query | string(date-time) |  | Fim (triggered_at <) |

**Respostas**

- `200` — Página de alertas

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Alert[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/alerts/{id}`
**Detalhe do alerta** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Alerta

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Alert |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/alerts/{id}/acknowledge`
**Reconhece o alerta (idempotente)** — papel mínimo: **operator**

Registra um evento no incidente. Enquanto a autenticação de usuários não existe (Fase 6), o autor é a chave administrativa.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `note` | string |  |  |

**Respostas**

- `200` — Alerta reconhecido

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Alert |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `409` — Alerta já resolvido (INVALID_STATE)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/alerts/{id}/resolve`
**Resolve o alerta manualmente (e fecha o incidente)** — papel mínimo: **operator**

Se a condição ainda existir, o avaliador abrirá um novo alerta quando voltar a avaliá-la como verdadeira (respeitando `duration_seconds`).

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Alerta resolvido

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Alert |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `409` — Alerta já resolvido (INVALID_STATE)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Incidentes

### `GET /api/v1/servers/{id}/incidents`
**Incidentes do servidor** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `status` | query | `open` \| `resolved` |  |  |
| `severity` | query | `info` \| `warning` \| `critical` |  |  |
| `from` | query | string(date-time) |  |  |
| `to` | query | string(date-time) |  |  |

**Respostas**

- `200` — Página de incidentes

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Incident[] | sim |  |
| `meta` | PageMeta | sim |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/notifications`
**Registro permanente de notificações (alertas disparados e recuperados, IPs banidos)** — papel mínimo: **viewer**

Toda notificação gerada fica gravada no PostgreSQL, com ou sem canal externo (Telegram) e independentemente da entrega.
Mais recentes primeiro. `meta.unread` traz o total de não lidas (todas, ignorando os filtros).

| Nome | Em | Tipo | Descrição |
|---|---|---|---|
| `page`, `per_page` | query | integer | Paginação |
| `kind` | query | `alert_triggered` \| `alert_resolved` \| `ip_banned` |  |
| `priority` | query | `1`–`4` |  |
| `server_id` | query | string(uuid) |  |
| `unread` | query | boolean |  |
| `from`, `to` | query | string(date-time) |  |

Resposta `200`: `data` = Notification[], `meta` = PageMeta + `unread`.

### `POST /api/v1/notifications/{id}/read`
**Marca uma notificação como lida (idempotente)** — papel mínimo: **operator**. `200` com a Notification; `404` se não existir.

### `POST /api/v1/notifications/read-all`
**Marca todas como lidas** — papel mínimo: **operator**. `200` com `{ "marked": n }`.

### `GET /api/v1/incidents`
**Lista incidentes (mais recentes primeiro)** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `page` | query | integer padrão 1 |  |  |
| `per_page` | query | integer padrão 20 máx 100 |  |  |
| `status` | query | `open` \| `resolved` |  |  |
| `severity` | query | Severity |  |  |
| `server_id` | query | string(uuid) |  |  |
| `from` | query | string(date-time) |  |  |
| `to` | query | string(date-time) |  |  |

**Respostas**

- `200` — Página de incidentes

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Incident[] | sim |  |
| `meta` | PageMeta | sim |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/incidents/{id}`
**Detalhe do incidente com seus alertas** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Incidente

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | IncidentDetail |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `GET /api/v1/incidents/{id}/events`
**Linha do tempo do incidente (ordem cronológica)** — papel mínimo: **viewer**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Eventos (opened, alert_triggered, acknowledged, alert_resolved, resolved)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | IncidentEvent[] |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Canais de notificação (Telegram)

### `GET /api/v1/notification-channels`
**Lista canais de notificação (nunca devolve o token)** — papel mínimo: **admin**

**Respostas**

- `200` — Canais

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | NotificationChannel[] |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/notification-channels`
**Cadastra um canal Telegram** — papel mínimo: **admin**

O `bot_token` é cifrado (AES-256-GCM) com `SECRETS_KEY` e nunca mais é exibido. O `chat_id` precisa estar em
`TELEGRAM_ALLOWED_CHAT_IDS` (ou ser o `TELEGRAM_CHAT_ID`); sem destinos autorizados nada é aceito.
Sem `SECRETS_KEY` a resposta é 503 `SECRETS_NOT_CONFIGURED`.
Entrega: fila persistente com retentativas e backoff exponencial; recuperação só é enviada a quem recebeu o disparo.

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string | sim |  |
| `channel_type` | `telegram` |  |  |
| `bot_token` | string | sim |  |
| `chat_id` | string | sim |  |
| `min_severity` | Severity |  |  |
| `is_enabled` | boolean |  |  |

**Respostas**

- `201` — Criado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | NotificationChannel |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After
- `503` — SECRETS_KEY não configurada

### `GET /api/v1/notification-channels/{id}`
**Detalhe do canal** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `200` — Canal

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | NotificationChannel |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `PATCH /api/v1/notification-channels/{id}`
**Altera o canal (inclusive trocar o token)** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string |  |  |
| `bot_token` | string |  |  |
| `chat_id` | string |  |  |
| `min_severity` | Severity |  |  |
| `is_enabled` | boolean |  |  |

**Respostas**

- `200` — Canal atualizado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | NotificationChannel |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After
- `503` — SECRETS_KEY não configurada

### `DELETE /api/v1/notification-channels/{id}`
**Remove o canal e suas mensagens pendentes** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `204` — Removido
- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/notification-channels/{id}/test`
**Enfileira uma mensagem de teste** — papel mínimo: **admin**

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `id` | path | string(uuid) | sim |  |

**Respostas**

- `202` — Enfileirada (entregue pelo worker em segundos)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object |  |  |
| `data.queued` | boolean |  |  |

- `400` — Identificador inválido (INVALID_ID)
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `404` — Recurso não encontrado
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

## Eventos em tempo real (SSE)

### `GET /api/v1/events`
**Stream de eventos em tempo real (Server-Sent Events)** — papel mínimo: **viewer**

Resposta `text/event-stream`, **fora do envelope** `{data, meta}` e **sem timeout de requisição**.
Cada mensagem tem o formato:

```
id: 123
event: alert.triggered
data: {"id":123,"type":"alert.triggered","time":"2026-03-01T12:00:00Z","data":{...}}
```

**Tipos.** `server.status_changed`, `alert.triggered`, `alert.acknowledged`, `alert.resolved`, `incident.created`,
`incident.resolved`, `service.status_changed` (duráveis, com `id`) e `metrics.updated` (efêmero, sem `id`, **opt-in**:
precisa constar em `types`; no máximo 1 a cada 5 s por servidor). O tipo sintético `resync` diz ao cliente para recarregar
o estado pela API (`reason`: `gap`, `ahead`, `too_many`, `overflow`, `error`).

**Reconexão.** Eventos duráveis têm `id` crescente em ordem de confirmação. Ao reconectar, envie `Last-Event-ID` (o
`EventSource` faz isso sozinho) ou `?last_event_id=`: o servidor reenvia o que faltou, em ordem e sem duplicar, e segue
ao vivo. Se o histórico não estiver mais disponível (retenção de `EVENTS_RETENTION_HOURS`, padrão 24 h), ou forem
eventos demais (> 1000), ou o id for de outro histórico, o servidor envia `resync`. Sem `Last-Event-ID` só chegam eventos novos.

**Mantém-se aberto** com comentários `: ping` a cada `SSE_HEARTBEAT_SECONDS` (padrão 15 s). `retry: 5000` sugere 5 s de espera
antes de reconectar. Um cliente que não acompanha o ritmo recebe `resync` (`overflow`) e é desconectado.

**Autorização.** Sessão de usuário (cookie), qualquer papel. O `EventSource` nativo funciona com `withCredentials: true`; clientes
baseados em `fetch` também podem usar `Authorization: Bearer <ADMIN_API_KEY>`. A chave **não** é aceita na URL (vazaria em logs).
Todos os usuários autenticados verão os mesmos eventos; os payloads não contêm segredos, URLs/alvos, hostnames, tokens nem notas de operadores.

**Limites.** `SSE_MAX_CLIENTS` (500) e `SSE_MAX_CLIENTS_PER_IP` (20): 503 `STREAM_UNAVAILABLE` / 429 `TOO_MANY_STREAMS`.
Atrás de Nginx: `proxy_buffering off;` e `proxy_read_timeout` maior que o heartbeat.

**Parâmetros**

| Nome | Em | Tipo | Obrig. | Descrição |
|---|---|---|---|---|
| `types` | query | string |  | Lista (vírgulas) de tipos desejados. Padrão: todos os duráveis (sem metrics.updated). |
| `server_id` | query | string(uuid) |  | Só eventos deste servidor |
| `last_event_id` | query | integer |  | Equivale ao cabeçalho Last-Event-ID (o cabeçalho tem precedência) |
| `Last-Event-ID` | header | integer |  |  |

**Respostas**

- `200` — Stream aberto
- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Papel insuficiente (FORBIDDEN), token CSRF ausente/inválido (CSRF_INVALID) ou origem não permitida (ORIGIN_NOT_ALLOWED)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After
- `503` — Limite de conexões ou servidor encerrando (STREAM_UNAVAILABLE)

## Operação

### `GET /healthz`
**Liveness** — sessão

**Respostas**

- `200` — Processo ativo

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object | sim |  |
| `data.status` | string |  |  |
| `data.version` | string |  |  |


### `GET /readyz`
**Readiness (verifica o PostgreSQL)** — sessão

**Respostas**

- `200` — Pronto

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object | sim |  |
| `data.status` | string |  |  |
| `data.database` | string |  |  |

- `503` — Dependência indisponível

### `GET /metrics`
**Métricas Prometheus da própria API** — sessão

Formato texto do Prometheus (fora do envelope). Restrinja o acesso no proxy reverso.

**Respostas**

- `200` — Métricas

## Agente (não é para o frontend)

### `POST /api/v1/agent/heartbeat`
**Sinal de presença e inventário** — token do agente

O servidor é sempre o associado à credencial; identificadores de servidor no corpo são rejeitados.

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `agent_version` | string | sim |  |
| `host` | Host |  |  |

**Respostas**

- `200` — Registrado

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object |  |  |
| `data.server_time` | string(date-time) |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Servidor desativado (SERVER_DISABLED)
- `413` — Corpo acima do limite (PAYLOAD_TOO_LARGE)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/agent/metrics`
**Envia uma amostra de métricas** — token do agente

Idempotente por (servidor, `collected_at`): reenviar a mesma amostra devolve 200 com
`duplicate: true` e não grava de novo. `collected_at` deve estar entre 1 hora no passado
e 2 minutos no futuro, em relação ao horário de recebimento. Contadores de rede são ACUMULADOS.
Memória usada = total − disponível.

**Corpo (application/json)**

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `agent_version` | string | sim |  |
| `collected_at` | string(date-time) | sim |  |
| `host` | Host |  |  |
| `cpu` | object | sim |  |
| `cpu.usage_percent` | number | sim |  |
| `cpu.count` | integer |  |  |
| `cpu.load_average` | object |  |  |
| `cpu.load_average.m1` | number |  |  |
| `cpu.load_average.m5` | number |  |  |
| `cpu.load_average.m15` | number |  |  |
| `memory` | object | sim |  |
| `memory.total_bytes` | integer(int64) | sim |  |
| `memory.used_bytes` | integer(int64) | sim |  |
| `memory.available_bytes` | integer(int64) | sim |  |
| `memory.swap_total_bytes` | integer(int64) |  |  |
| `memory.swap_used_bytes` | integer(int64) |  |  |
| `network` | object |  | Contadores acumulados desde o boot (não são taxas) |
| `network.rx_bytes_total` | integer(int64) |  |  |
| `network.tx_bytes_total` | integer(int64) |  |  |
| `disks` | object[] |  |  |
| `disks[].mount_point` | string | sim | Caminho absoluto; sem duplicatas na mesma coleta |
| `disks[].filesystem` | string |  |  |
| `disks[].total_bytes` | integer(int64) | sim |  |
| `disks[].used_bytes` | integer(int64) | sim |  |
| `disks[].available_bytes` | integer(int64) | sim |  |

**Respostas**

- `200` — Aceita

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object |  |  |
| `data.stored` | boolean |  |  |
| `data.duplicate` | boolean |  |  |
| `data.received_at` | string(date-time) |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Servidor desativado (SERVER_DISABLED)
- `413` — Corpo acima do limite (PAYLOAD_TOO_LARGE)
- `422` — Dados inválidos (VALIDATION_ERROR) com detalhes por campo
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

### `POST /api/v1/agent/discovery`
**Serviços do sistema encontrados no host** — token do agente

Retrato completo dos serviços do catálogo (substitui o anterior). O agente só informa fatos de vocabulário fechado (`key`, `status`, `source`, `unit`); o texto de `action` é gerado pela API. Relatório mais antigo que o já gravado é ignorado.

**Corpo (application/json)**: `{"checked_at": "...", "services": [{"key": "ssh", "status": "available", "source": "systemd", "unit": "ssh.service"}, {"key": "redis", "status": "not_found"}]}`

### `GET /api/v1/agent/config`
**Parâmetros operacionais do agente (sem segredos nem comandos)** — token do agente

**Respostas**

- `200` — Configuração

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | object |  |  |
| `data.collect_interval_seconds` | integer |  |  |
| `data.heartbeat_timeout_seconds` | integer |  |  |
| `data.max_payload_bytes` | integer |  |  |
| `data.max_disks` | integer |  |  |

- `401` — Credencial ausente, inválida, expirada ou revogada
- `403` — Servidor desativado (SERVER_DISABLED)
- `429` — Limite de requisições excedido (RATE_LIMITED); veja o cabeçalho Retry-After

---

# Modelos (schemas)

### AdminStatus

Estado administrativo (definido pelo operador)

Tipo: `active` \| `maintenance` \| `disabled`

### ConnectionStatus

Calculado a partir de last_seen_at e AGENT_HEARTBEAT_TIMEOUT_SECONDS; `unknown` = nunca recebeu comunicação

Tipo: `online` \| `offline` \| `unknown`

### Server

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `name` | string |  |  |
| `hostname` | string |  |  |
| `operating_system` | string \| null |  |  |
| `operating_system_version` | string \| null |  |  |
| `architecture` | string \| null |  |  |
| `agent_version` | string \| null |  |  |
| `status` | AdminStatus |  |  |
| `connection_status` | ConnectionStatus |  |  |
| `last_seen_at` | string(date-time) \| null |  |  |
| `created_at` | string(date-time) |  |  |
| `updated_at` | string(date-time) |  |  |

### ServerEnvelope

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `data` | Server | sim |  |

### PageMeta

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `page` | integer |  |  |
| `per_page` | integer |  |  |
| `total` | integer |  |  |
| `total_pages` | integer |  |  |

### Disk

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `mount_point` | string |  |  |
| `filesystem` | string \| null |  |  |
| `total_bytes` | integer(int64) |  |  |
| `used_bytes` | integer(int64) |  |  |
| `available_bytes` | integer(int64) |  |  |
| `used_percent` | number |  |  |
| `collected_at` | string(date-time) |  |  |

### Credential

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `server_id` | string(uuid) |  |  |
| `created_at` | string(date-time) |  |  |
| `expires_at` | string(date-time) \| null |  |  |
| `revoked_at` | string(date-time) \| null |  |  |
| `last_used_at` | string(date-time) \| null |  |  |

### IssuedCredential

Tipo: any

### Host

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `hostname` | string |  |  |
| `os` | string |  |  |
| `os_version` | string |  |  |
| `architecture` | string |  |  |
| `uptime_seconds` | integer(int64) |  |  |

### Heartbeat

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `agent_version` | string | sim |  |
| `host` | Host |  |  |

### MetricsPayload

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `agent_version` | string | sim |  |
| `collected_at` | string(date-time) | sim |  |
| `host` | Host |  |  |
| `cpu` | object | sim |  |
| `cpu.usage_percent` | number | sim |  |
| `cpu.count` | integer |  |  |
| `cpu.load_average` | object |  |  |
| `cpu.load_average.m1` | number |  |  |
| `cpu.load_average.m5` | number |  |  |
| `cpu.load_average.m15` | number |  |  |
| `memory` | object | sim |  |
| `memory.total_bytes` | integer(int64) | sim |  |
| `memory.used_bytes` | integer(int64) | sim |  |
| `memory.available_bytes` | integer(int64) | sim |  |
| `memory.swap_total_bytes` | integer(int64) |  |  |
| `memory.swap_used_bytes` | integer(int64) |  |  |
| `network` | object |  | Contadores acumulados desde o boot (não são taxas) |
| `network.rx_bytes_total` | integer(int64) |  |  |
| `network.tx_bytes_total` | integer(int64) |  |  |
| `disks` | object[] |  |  |
| `disks[].mount_point` | string | sim | Caminho absoluto; sem duplicatas na mesma coleta |
| `disks[].filesystem` | string |  |  |
| `disks[].total_bytes` | integer(int64) | sim |  |
| `disks[].used_bytes` | integer(int64) | sim |  |
| `disks[].available_bytes` | integer(int64) | sim |  |

### Stat

Mínimo, média e máximo no balde (nulos quando não há dado, por exemplo sem swap ou sem taxa válida)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `min` | number \| null |  |  |
| `avg` | number \| null |  |  |
| `max` | number \| null |  |  |

### SeriesMeta

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `from` | string(date-time) |  |  |
| `to` | string(date-time) |  |  |
| `interval` | string |  |  |
| `bucket_seconds` | integer |  | 0 = amostras originais |
| `points` | integer |  |  |
| `max_points` | integer |  |  |

### MetricPoint

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `t` | string(date-time) |  | Início do balde (ou instante da amostra em raw) |
| `samples` | integer |  |  |
| `cpu_usage_percent` | Stat |  |  |
| `memory_used_percent` | Stat |  |  |
| `memory_used_bytes` | Stat |  |  |
| `load_average_1m` | Stat |  |  |
| `swap_used_percent` | Stat |  |  |
| `network_rx_bytes_per_sec` | Stat |  |  |
| `network_tx_bytes_per_sec` | Stat |  |  |

### AggregatedPoint

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `t` | string(date-time) |  |  |
| `samples` | integer |  |  |
| `servers` | integer |  | Servidores distintos com dados no balde |
| `cpu_usage_percent` | Stat |  |  |
| `memory_used_percent` | number \| null |  | Σ usado / Σ total |
| `load_average_1m` | Stat |  |  |

### Capacity

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `used_bytes` | integer(int64) |  |  |
| `total_bytes` | integer(int64) |  |  |
| `used_percent` | number \| null |  |  |

### AlertCounts

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `active` | integer |  |  |
| `critical` | integer |  |  |
| `warning` | integer |  |  |
| `info` | integer |  |  |

### DashboardSummary

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `servers` | object |  |  |
| `servers.total` | integer |  |  |
| `servers.online` | integer |  |  |
| `servers.offline` | integer |  |  |
| `servers.unknown` | integer |  |  |
| `servers.maintenance` | integer |  |  |
| `servers.disabled` | integer |  |  |
| `servers.with_active_alerts` | integer |  |  |
| `alerts` | AlertCounts |  |  |
| `incidents` | object |  |  |
| `incidents.open` | integer |  |  |
| `resources` | object |  |  |
| `resources.reporting_servers` | integer |  | Servidores online usados nos agregados |
| `resources.cpu` | object |  |  |
| `resources.cpu.weighted_avg_percent` | number \| null |  |  |
| `resources.cpu.max_percent` | number \| null |  |  |
| `resources.cpu.top_server` | object |  |  |
| `resources.cpu.top_server.id` | string(uuid) |  |  |
| `resources.cpu.top_server.name` | string |  |  |
| `resources.cpu.distribution` | object |  |  |
| `resources.cpu.distribution.low` | integer |  |  |
| `resources.cpu.distribution.medium` | integer |  |  |
| `resources.cpu.distribution.high` | integer |  |  |
| `resources.memory` | Capacity |  |  |
| `resources.disk` | Capacity |  |  |
| `data_as_of` | string(date-time) \| null |  | Recebimento mais recente entre as amostras usadas |
| `updated_at` | string(date-time) |  |  |

### ServerSummary

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `server` | Server |  |  |
| `latest` | object |  |  |
| `latest.collected_at` | string(date-time) |  |  |
| `latest.received_at` | string(date-time) |  |  |
| `latest.cpu_usage_percent` | number |  |  |
| `latest.cpu_count` | integer \| null |  |  |
| `latest.load_average` | object |  |  |
| `latest.load_average.m1` | number \| null |  |  |
| `latest.load_average.m5` | number \| null |  |  |
| `latest.load_average.m15` | number \| null |  |  |
| `latest.memory` | object |  |  |
| `latest.memory.total_bytes` | integer(int64) |  |  |
| `latest.memory.used_bytes` | integer(int64) |  |  |
| `latest.memory.available_bytes` | integer(int64) |  |  |
| `latest.memory.used_percent` | number \| null |  |  |
| `latest.memory.swap_total_bytes` | integer(int64) |  |  |
| `latest.memory.swap_used_bytes` | integer(int64) |  |  |
| `latest.uptime_seconds` | integer \| null |  |  |
| `latest.network` | object |  |  |
| `latest.network.rx_bytes_per_sec` | number |  |  |
| `latest.network.tx_bytes_per_sec` | number |  |  |
| `disks` | Disk[] |  |  |
| `alerts` | AlertCounts |  |  |
| `incidents` | object |  |  |
| `incidents.open` | integer |  |  |
| `services` | object |  |  |
| `services.total` | integer |  |  |
| `services.up` | integer |  |  |
| `services.down` | integer |  |  |
| `services.degraded` | integer |  |  |
| `services.unknown` | integer |  |  |
| `availability` | object |  |  |
| `availability.window_seconds` | integer |  |  |
| `availability.percent` | number \| null |  |  |

### RecentAlert

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `server_id` | string(uuid) |  |  |
| `server_name` | string |  |  |
| `rule_id` | string(uuid) |  |  |
| `rule_name` | string |  |  |
| `severity` | `info` \| `warning` \| `critical` |  |  |
| `status` | `pending` \| `firing` \| `acknowledged` \| `resolved` |  |  |
| `message` | string |  |  |
| `triggered_at` | string(date-time) |  |  |
| `acknowledged_at` | string(date-time) \| null |  |  |
| `resolved_at` | string(date-time) \| null |  |  |

### RecentIncident

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `server_id` | string(uuid) \| null |  |  |
| `server_name` | string \| null |  |  |
| `title` | string |  |  |
| `severity` | `info` \| `warning` \| `critical` |  |  |
| `status` | `open` \| `resolved` |  |  |
| `started_at` | string(date-time) |  |  |
| `resolved_at` | string(date-time) \| null |  |  |
| `duration_seconds` | integer(int64) |  |  |

### Severity

Tipo: `info` \| `warning` \| `critical`

### MetricName

Tipo: `cpu_usage_percent` \| `memory_used_percent` \| `disk_used_percent` \| `load_average_1m` \| `server_offline` \| `service_down` \| `swap_used_percent` \| `load_per_cpu` \| `oom_kills_10m` \| `inode_used_percent` \| `disk_latency_ms` \| `ntp_unsynchronized` \| `security_updates` \| `cert_days_left`

### ServiceConfig

Mantido por compatibilidade; sem efeito (os serviços são descobertos automaticamente).

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `timeout_seconds` | integer |  |  |
| `interval_seconds` | integer |  |  |

### Service

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `server_id` | string(uuid) |  |  |
| `name` | string |  |  |
| `service_type` | `discovered` |  |  |
| `target` | string |  |  |
| `config` | ServiceConfig |  |  |
| `status` | `unknown` \| `up` \| `down` \| `degraded` |  |  |
| `last_checked_at` | string(date-time) \| null |  |  |
| `last_error` | string \| null |  |  |
| `last_latency_ms` | integer \| null |  |  |
| `last_status_code` | integer \| null |  |  |
| `consecutive_failures` | integer |  |  |
| `status_changed_at` | string(date-time) \| null |  |  |
| `created_at` | string(date-time) |  |  |
| `updated_at` | string(date-time) |  |  |

### AlertRule

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `code` | string \| null |  | Identificador estável da regra do catálogo |
| `name` | string |  |  |
| `description` | string |  |  |
| `metric_name` | MetricName |  |  |
| `operator` | `>` \| `>=` \| `<` \| `<=` \| `==` |  |  |
| `threshold` | number |  |  |
| `priority` | Priority |  |  |
| `severity` | Severity |  |  |
| `duration_seconds` | integer |  | Tempo com a condição verdadeira antes de alertar |
| `recovery_seconds` | integer |  | Tempo com a condição normalizada antes de resolver |
| `server_id` | string(uuid) \| null |  | Sempre nulo; as regras valem para todos os servidores |
| `is_enabled` | boolean |  |  |
| `created_at` | string(date-time) |  |  |
| `updated_at` | string(date-time) |  |  |

### Notification

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | integer(int64) |  |
| `kind` | `alert_triggered` \| `alert_resolved` \| `ip_banned` |  |
| `priority` | Priority | Recuperação = 4; IP banido = 3 |
| `severity` | Severity |  |
| `server_id`, `server_name` | string \| null |  |
| `alert_id`, `incident_id` | string(uuid) \| null |  |
| `title`, `message` | string |  |
| `data` | object | Cópia do conteúdo enviado |
| `created_at` | string(date-time) |  |
| `read_at` | string(date-time) \| null |  |

### Priority

Inteiro `1`–`4`: P1 crítico (notificação imediata), P2 alto, P3 atenção (aparece no painel), P4 informativo (histórico). P1 e P2 têm severidade `critical`, P3 `warning` e P4 `info`.

### Alert

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `rule_id` | string(uuid) |  |  |
| `rule_name` | string |  |  |
| `server_id` | string(uuid) |  |  |
| `server_name` | string |  |  |
| `service_id` | string(uuid) \| null |  |  |
| `service_name` | string \| null |  |  |
| `incident_id` | string(uuid) \| null |  |  |
| `status` | `firing` \| `acknowledged` \| `resolved` |  |  |
| `priority` | Priority |  |  |
| `severity` | Severity |  |  |
| `message` | string |  |  |
| `value` | number \| null |  |  |
| `triggered_at` | string(date-time) |  |  |
| `acknowledged_at` | string(date-time) \| null |  |  |
| `acknowledged_by` | string(uuid) \| null |  | Usuário (Fase 6); nulo enquanto o ator é a chave administrativa |
| `resolved_at` | string(date-time) \| null |  |  |
| `resolved_reason` | `recovered` \| `manual` \| `rule_disabled` \| `rule_deleted` \| `out_of_scope` |  |  |
| `last_evaluated_at` | string(date-time) |  |  |

### Incident

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `server_id` | string(uuid) \| null |  |  |
| `server_name` | string \| null |  |  |
| `rule_id` | string(uuid) \| null |  |  |
| `rule_name` | string \| null |  |  |
| `service_id` | string(uuid) \| null |  |  |
| `service_name` | string \| null |  |  |
| `title` | string |  |  |
| `severity` | Severity |  |  |
| `priority` | Priority |  |  |
| `recurrence_count` | integer |  | Incidentes iguais (mesmo servidor, regra e serviço) resolvidos nas 24 h anteriores; maior que 0 = reincidente |
| `status` | `open` \| `resolved` |  |  |
| `started_at` | string(date-time) |  |  |
| `resolved_at` | string(date-time) \| null |  |  |
| `duration_seconds` | integer(int64) |  | Incidente aberto = tempo decorrido até agora |

### IncidentDetail

Tipo: any

### IncidentEvent

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | integer(int64) |  |  |
| `event_type` | `opened` \| `alert_triggered` \| `acknowledged` \| `alert_resolved` \| `resolved` |  |  |
| `message` | string |  |  |
| `created_at` | string(date-time) |  |  |

### CreateChannel

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `name` | string | sim |  |
| `channel_type` | `telegram` |  |  |
| `bot_token` | string | sim |  |
| `chat_id` | string | sim |  |
| `min_severity` | Severity |  |  |
| `is_enabled` | boolean |  |  |

### NotificationChannel

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `name` | string |  |  |
| `channel_type` | `telegram` |  |  |
| `chat_id` | string |  |  |
| `min_severity` | Severity |  |  |
| `is_enabled` | boolean |  |  |
| `has_token` | boolean |  | O token nunca é devolvido |
| `created_at` | string(date-time) |  |  |
| `updated_at` | string(date-time) |  |  |

### EventEnvelope

Conteúdo de `data:` de cada mensagem SSE

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | integer(int64) |  | Ausente nos eventos efêmeros (metrics.updated) |
| `type` | `server.status_changed` \| `metrics.updated` \| `alert.triggered` \| `alert.acknowledged` \| `alert.resolved` \| `incident.created` \| `incident.resolved` \| `service.status_changed` \| `resync` | sim |  |
| `time` | string(date-time) | sim |  |
| `data` | any | sim |  |

### AlertEventData

alert.triggered / alert.acknowledged / alert.resolved

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `alert_id` | string(uuid) |  |  |
| `incident_id` | string(uuid) |  |  |
| `server_id` | string(uuid) |  |  |
| `server_name` | string |  |  |
| `service_id` | string(uuid) |  |  |
| `service_name` | string |  |  |
| `rule_id` | string(uuid) |  |  |
| `rule_name` | string |  |  |
| `severity` | Severity |  |  |
| `status` | `firing` \| `acknowledged` \| `resolved` |  |  |
| `message` | string |  |  |
| `at` | string(date-time) |  |  |

### IncidentEventData

incident.created / incident.resolved

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `incident_id` | string(uuid) |  |  |
| `server_id` | string(uuid) |  |  |
| `server_name` | string |  |  |
| `service_id` | string(uuid) |  |  |
| `service_name` | string |  |  |
| `rule_id` | string(uuid) |  |  |
| `rule_name` | string |  |  |
| `title` | string |  |  |
| `severity` | Severity |  |  |
| `status` | `open` \| `resolved` |  |  |
| `started_at` | string(date-time) |  |  |
| `resolved_at` | string(date-time) |  |  |

### ServiceStatusEventData

service.status_changed (sem alvo nem mensagem de erro)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `service_id` | string(uuid) |  |  |
| `server_id` | string(uuid) |  |  |
| `server_name` | string |  |  |
| `name` | string |  |  |
| `service_type` | `discovered` |  |  |
| `previous_status` | `unknown` \| `up` \| `down` \| `degraded` |  |  |
| `status` | `unknown` \| `up` \| `down` \| `degraded` |  |  |
| `checked_at` | string(date-time) |  |  |

### ServerStatusEventData

server.status_changed. Dois casos: mudança de conectividade (`connection_status` + `previous_connection_status`) ou do estado
administrativo (`status` + `previous_status`). `connection_status` e `status` sempre trazem o valor atual.

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `server_id` | string(uuid) |  |  |
| `name` | string |  |  |
| `status` | `active` \| `maintenance` \| `disabled` |  |  |
| `previous_status` | string |  |  |
| `connection_status` | `online` \| `offline` \| `unknown` |  |  |
| `previous_connection_status` | string |  |  |
| `at` | string(date-time) |  |  |

### MetricsUpdatedEventData

metrics.updated (efêmero; mínimo para atualizar cards)

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `server_id` | string(uuid) |  |  |
| `collected_at` | string(date-time) |  |  |
| `cpu_usage_percent` | number |  |  |
| `memory_used_percent` | number \| null |  |  |

### ResyncEventData

O cliente deve recarregar o estado pela API REST e continuar ouvindo

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `reason` | `gap` \| `ahead` \| `too_many` \| `overflow` \| `error` |  |  |

### UserRole

viewer < operator < admin; cada operação documenta `x-required-role`

Tipo: `viewer` \| `operator` \| `admin`

### User

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | string(uuid) |  |  |
| `name` | string |  |  |
| `email` | string(email) |  |  |
| `role` | UserRole |  |  |
| `is_active` | boolean |  |  |
| `created_at` | string(date-time) |  |  |
| `updated_at` | string(date-time) |  |  |
| `last_login_at` | string(date-time) \| null |  |  |
| `password_changed_at` | string(date-time) |  |  |

### SessionInfo

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `user` | User |  |  |
| `via` | `session` \| `api_key` |  |  |
| `csrf_token` | string |  | Enviar em X-CSRF-Token nas requisições que alteram estado |
| `expires_at` | string(date-time) |  | Fim absoluto da sessão |
| `idle_expires_at` | string(date-time) |  | Vence se não houver uso até este instante (renova a cada uso) |

### AuditEntry

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `id` | integer(int64) |  |  |
| `action` | string |  |  |
| `resource_type` | string |  |  |
| `resource_id` | string \| null |  |  |
| `actor` | string |  | E-mail do usuário, `api_key` ou `sistema` |
| `actor_user_id` | string(uuid) \| null |  |  |
| `ip` | string \| null |  |  |
| `metadata` | object |  |  |
| `created_at` | string(date-time) |  |  |

### Error

| Campo | Tipo | Obrig. | Descrição |
|---|---|---|---|
| `error` | object | sim |  |
| `error.code` | string | sim |  |
| `error.message` | string | sim |  |
| `error.details` | object[] | sim |  |
| `error.details[].field` | string |  |  |
| `error.details[].message` | string | sim |  |

