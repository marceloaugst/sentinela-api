# Segurança

Resumo do modelo de ameaças, das decisões e dos controles. O que está aqui corresponde ao código e é verificado por testes
(automatizados, inclusive de mutação: quebrar o controle faz um teste falhar).

## 1. Autenticação (decidida antes de implementar)
| Decisão | Escolha | Motivo |
|---|---|---|
| Credencial do navegador | **Sessão opaca no servidor** em cookie `HttpOnly` | Revogável na hora (logout, desativação, troca de senha); sem JWT para invalidar. |
| Token | 256 bits aleatórios (`ses_…`); no banco só o **SHA-256** | Vazamento do banco não permite sequestrar sessões. |
| Cookie | `HttpOnly`, `Secure` (produção), `SameSite=Lax`, `Path=/`, sem `Domain`; prefixo **`__Host-`** quando `Secure` | JS não lê o cookie; subdomínios não o sobrescrevem. |
| Vida da sessão | Prazo **absoluto** 24 h + **inatividade** 2 h (renovada por uso, ≤ 1 gravação/min) | Limita o dano de um cookie roubado. |
| Renovação do token | Token **novo a cada login** e a cada troca de senha | Sem fixação de sessão. |
| CSRF | Token derivado por HMAC-SHA256 do token da sessão, em `X-CSRF-Token`, **mais** verificação de `Origin` | Sem estado extra; `/auth/me` reemite após recarregar. Só métodos que alteram estado. |
| Senhas | **Argon2id** (padrão 64 MiB, t=3, p=2; produção exige ≥ 19 MiB e t ≥ 2), parâmetros dentro do hash | Rehash transparente no login ao subir o custo. Concorrência de hashes limitada (4). |
| Política de senha | 12–128 caracteres, sem senhas comuns/sequências, sem conter e-mail ou nome | Prioriza comprimento (NIST 800-63B). |
| Cadastro | **Não existe cadastro público.** Admin cria usuários; o 1º admin vem de `create-admin` ou `ADMIN_BOOTSTRAP_*` | — |
| Chave de automação | `ADMIN_API_KEY` (opcional, **vazia por padrão**): Bearer, papel `admin`, sem cookie/CSRF, auditada como `api_key` | Para scripts/CI. Em produção prefira deixá-la vazia. Não há 2º fator. |
| Agentes | Token individual por servidor (`snt_…`, hash SHA-256), revogável/expirável, rate limit próprio | Credenciais de agente e de usuário **não são intercambiáveis** (testado). |

**Frontend em outra origem:** configure `CORS_ALLOWED_ORIGINS` (lista exata, sem `*`), `COOKIE_SAMESITE=none` + `COOKIE_SECURE=true`, e `fetch(..., {credentials: "include"})`. O `Origin` das requisições que alteram estado precisa estar nessa lista.

## 2. Autorização por papel
`viewer < operator < admin`, declarada **uma vez por rota** (`internal/http/router.go`) e verificada no servidor em toda requisição (o papel é lido do banco: rebaixar ou desativar vale na próxima requisição).

| Papel | Pode |
|---|---|
| `viewer` | Ler: servidores, métricas, dashboard, serviços, regras, alertas, incidentes, eventos (SSE). |
| `operator` | Tudo do viewer + reconhecer/resolver alertas, executar verificação de serviço, **criar/alterar/remover serviços e regras de alerta**. |
| `admin` | Tudo + servidores, **credenciais de agente**, **canais de notificação**, **usuários**, **auditoria**. |

- Canais de notificação e credenciais ficam só com `admin` (contêm destinos e segredos).
- Não há multi-organização: a aplicação é de um único tenant. "Acesso a dados de outros usuários" é coberto pela separação de papéis; só `admin` lê/altera contas.
- O **último administrador ativo** não pode ser desativado nem rebaixado (nem por concorrência: linhas travadas na transação).
- Desativar um usuário ou redefinir sua senha **revoga todas as sessões** na mesma transação, e **encerra os streams SSE** dele (revalidados a cada ping).
- **Teste de matriz:** gerado a partir do registro de rotas — cada rota é chamada sem autenticação (401), com cada papel insuficiente (403) e com cada papel suficiente (nunca 401/403). Rota nova sem papel declarado quebra o teste; o OpenAPI (`x-required-role`) é comparado com o roteador.

## 3. Força bruta e abuso
| Controle | Detalhe |
|---|---|
| Bloqueio de login (429 `LOGIN_LOCKED`, `Retry-After`) | 5 falhas do mesmo e-mail **a partir do mesmo IP**; 20 falhas de um IP (credential stuffing); 30 falhas do mesmo e-mail em IPs distintos — janela/bloqueio de 15 min, que se desfaz sozinho. Verificado **antes** de checar a senha; tentativas bloqueadas não prolongam o bloqueio. |
| Sem DoS de conta | O escopo (e-mail, IP) impede que um atacante em outro IP tranque o usuário legítimo (testado). O bloqueio global por e-mail (30) é o compromisso contra ataques distribuídos. |
| Sem enumeração de contas | Senha errada, e-mail inexistente, conta desativada e e-mail malformado: **mesma resposta e mesmo tempo** (hash fantasma; teste de tempo). |
| Limite de taxa | Login 5 req/s por IP (burst 10); API 30 req/s por IP (burst 100); agentes 2 req/s por credencial e 20/s por IP. Em memória, **por instância**. No Nginx há uma segunda camada. |
| Troca de senha | Exige a senha atual; erros contam para o bloqueio. |
| Limites | Corpo 1 MiB (login 8 KiB, agentes 64 KiB), senha ≤ 1 KiB, timeouts HTTP, JSON estrito (campos desconhecidos recusados). |

## 4. Cabeçalhos e transporte
HTTPS é terminado no Nginx (a API escuta em `127.0.0.1`). Respostas levam `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cross-Origin-Resource-Policy: same-site`; HSTS em produção. Respostas autenticadas: `Cache-Control: no-store`. Stack traces e erros de banco nunca chegam ao cliente.

## 5. Dados sensíveis
| Dado | Proteção |
|---|---|
| Senhas | Argon2id; nunca registradas, devolvidas ou auditadas. |
| Tokens de sessão/agente | Só o SHA-256 no banco; token de agente exibido uma única vez. |
| Token do bot (Telegram) | AES-256-GCM com `SECRETS_KEY` (fora do banco); nunca devolvido; erros do Telegram têm o token mascarado. |
| Auditoria | `Redact` mascara chaves `token/password/secret/key/hash`; teste varre `audit_logs` por senhas, hashes, tokens e CSRF. |
| Eventos SSE | Payloads mínimos, sem alvos de serviço, URLs, hostnames, mensagens de erro brutas ou notas de operadores. |
| Logs | Contêm `user_id`/`actor` e `request_id`; não contêm corpo de requisição, cookies nem cabeçalhos de autorização. |

## 6. Agente e injeção
- A API **não faz requisições a alvos informados por usuários** (não há mais verificação `http` nem cadastro de serviços), então não há superfície de SSRF.
- O agente não executa comandos nem abre conexões a pedido da API: a descoberta só lê `/proc`, cgroup e arquivos de unit. O texto "o que fazer" é gerado pela API a partir de um vocabulário fechado.
- SQL: somente consultas parametrizadas; ordenações por lista permitida.

## 7. Auditoria
`GET /api/v1/audit-logs` (admin): quem (`actor`, `actor_user_id`), o quê, em qual recurso, de qual IP e quando — login e bloqueios, usuários, servidores, credenciais, serviços, regras, canais, reconhecimento/resolução de alertas. Retenção `AUDIT_RETENTION_DAYS` (365). Não há tela de "configurações" mutável: a configuração é por variáveis de ambiente (alterá-las exige redeploy e fica no controle de versão do operador).

## 8. Limitações conhecidas (e o que fazer)
| Limitação | Mitigação / próximo passo |
|---|---|
| Sem 2º fator (TOTP) | Planejado como evolução; proteja o acesso por VPN/allowlist de IP no Nginx se necessário. |
| Sem recuperação de senha por e-mail | Um admin redefine (`PATCH /users/{id}`) ou o operador usa `sentinela-api reset-password`. |
| Rate limit por instância | Com N instâncias o limite efetivo é N×; o Nginx e os bloqueios de login (no banco) são globais. Para limite global, usar Redis. |
| `ADMIN_API_KEY` sem 2º fator | Deixe vazia; se usar, restrinja por IP no Nginx e rotacione. |
| Rotação da `SECRETS_KEY` | Não há re-cifragem automática: recadastre os tokens dos canais (`PATCH` com `bot_token`) após trocar a chave. |
| Bloqueio global por e-mail (30 falhas) permite negar login a um alvo por 15 min a um atacante distribuído | Compromisso consciente; o par (e-mail, IP) protege o caso comum. Alerta: monitore `auth.login_locked` na auditoria. |

## 9. Checklist de produção
- [ ] `APP_ENV=production` (força `COOKIE_SECURE`, Argon2id ≥ OWASP, HSTS).
- [ ] HTTPS válido no Nginx; API só em `127.0.0.1`; PostgreSQL sem porta publicada.
- [ ] `POSTGRES_PASSWORD`, `SECRETS_KEY` e `METRICS_TOKEN` gerados com `openssl rand` e fora do repositório.
- [ ] `ADMIN_API_KEY` vazia (ou restrita por IP); `ADMIN_BOOTSTRAP_PASSWORD` removida após o 1º start.
- [ ] `TRUST_PROXY=true` **somente** com o Nginx na frente (e a porta 8080 inacessível de fora).
- [ ] `CORS_ALLOWED_ORIGINS` explícito (ou vazio se o frontend é do mesmo domínio).
- [ ] `/metrics` restrito no Nginx e com `METRICS_TOKEN`.
- [ ] Backups agendados **e restauração testada**; `SECRETS_KEY` guardada à parte.
- [ ] Firewall (`ufw`): só 22/80/443.
