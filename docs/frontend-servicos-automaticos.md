# Serviços automáticos — guia de migração do front

O cadastro manual de serviços **acabou**. O agente descobre sozinho os serviços de cada servidor e a API apenas mostra o resultado. Este guia lista o que o front deve **remover**, o que deve **implementar** e como ligar tudo aos alertas.

Convenções: base `/api/v1`, envelope `{ "data": ..., "meta": ... }`, mesma autenticação de sempre (cookie + CSRF nas escritas). Contrato completo em `api/openapi.yaml`.

---

## 1. Métodos desativados

Qualquer chamada a estas rotas deixa de funcionar (rota inexistente → `404`/`405`). **Remova do front** as telas, formulários, botões e chamadas correspondentes.

| Método | Rota | Antes servia para | O que fazer no front |
|---|---|---|---|
| `POST` | `/services` | Cadastrar serviço | Remover o botão "Novo serviço" e o formulário |
| `PATCH` | `/services/{id}` | Editar serviço | Remover a edição (nome, alvo, intervalo, timeout) |
| `DELETE` | `/services/{id}` | Excluir serviço | Remover o botão de excluir |
| `POST` | `/services/{id}/check` | "Verificar agora" | Remover o botão (a descoberta roda sozinha a cada ~1 min) |
| `POST` | `/agent/services` | Agente reportar serviços | Só o agente usava; o front nunca chamou |

Também deixaram de existir:

- **Tipos `http`, `tcp` e `systemd`.** `service_type` agora é sempre `"discovered"`. Remova seletores/filtros por tipo e os campos específicos de cada tipo (URL, host/porta, método HTTP, status esperado, nome da unit).
- **Monitoramento de URL (`http`).** Não existe mais verificação de endpoint por URL.
- **Campo `services` em `GET /agent/config`.** Só o agente lê essa rota; não afeta o front.
- **Serviços antigos.** Os cadastrados manualmente foram arquivados pela migração `0011` e **não aparecem mais** nas listagens.

> Dica: faça uma busca no código do front por `/services`, `service_type`, `ServiceForm` e `check` para achar tudo o que precisa sair.

---

## 2. Métodos que continuam (somente leitura)

| Método | Rota | Papel mínimo | Mudança |
|---|---|---|---|
| `GET` | `/services` | viewer | `service_type` sempre `discovered`; filtro `service_type` só aceita `discovered` |
| `GET` | `/services/{id}` | viewer | igual |
| `GET` | `/servers/{id}/services` | viewer | igual |

Filtros de `GET /services`: `page`, `per_page` (máx. 100), `q`, `server_id`, `status` (`up|down|degraded|unknown`), `service_type` (`discovered`).

Objeto `Service` (campos relevantes):

```json
{
  "id": "uuid",
  "server_id": "uuid",
  "name": "SSH (automático)",
  "service_type": "discovered",
  "status": "up",
  "last_checked_at": "2026-10-22T12:00:00Z",
  "last_error": null,
  "status_changed_at": "2026-10-22T11:40:00Z"
}
```

- `name` sempre termina com `(automático)`.
- Quando `status = "down"`, `last_error` traz o motivo fixo: `instalado, mas parado ou desativado` ou `não encontrado (parou ou foi removido)`.
- Campos de verificação manual (`target`, `config`, `last_latency_ms`, `last_status_code`, `consecutive_failures`) ainda existem no JSON por compatibilidade, mas **não têm significado** para serviços descobertos. Não exiba.
- Só entram nessa lista serviços que **já foram vistos disponíveis**. Um serviço que nunca existiu no servidor (ex.: Redis não instalado) não vira "down" nem gera alerta — ele aparece apenas na descoberta (seção 3).

---

## 3. Novo método: descoberta

### `GET /servers/{id}/discovery` — papel mínimo: viewer

Retorna o panorama dos serviços de **um servidor**: o que está disponível, o que não está e **o que fazer** para ficar disponível.

Serviços cobertos (ordem fixa, igual à da resposta): `ssh`, `journald`, `cron`, `timesyncd`, `ufw`, `rsyslog`, `nginx`, `redis`, `docker`, `postgresql`. Redis e PostgreSQL são procurados no host e, se não estiverem lá, em containers Docker.

**Resposta `200`**

```json
{
  "data": {
    "summary": { "total": 10, "available": 8, "unavailable": 2 },
    "checked_at": "2026-10-22T12:00:00Z",
    "services": [
      {
        "key": "ssh",
        "name": "SSH",
        "available": true,
        "status": "available",
        "source": "systemd",
        "unit": "ssh.service",
        "action": "",
        "checked_at": "2026-10-22T12:00:00Z",
        "status_changed_at": "2026-10-20T08:00:00Z"
      },
      {
        "key": "timesyncd",
        "name": "systemd-timesyncd",
        "available": false,
        "status": "not_found",
        "source": "",
        "unit": "",
        "action": "sudo apt install systemd-timesyncd && sudo systemctl enable --now systemd-timesyncd",
        "checked_at": "2026-10-22T12:00:00Z",
        "status_changed_at": "2026-10-20T08:00:00Z"
      }
    ]
  }
}
```

| Campo | Tipo | Observações |
|---|---|---|
| `summary` | `{total, available, unavailable}` | Para o cabeçalho do painel |
| `checked_at` | date-time \| `null` | `null` = agente ainda não reportou |
| `services[].key` | string | Identificador estável (use como chave de lista) |
| `services[].name` | string | Nome para exibir |
| `services[].available` | boolean | `true` = em execução |
| `services[].status` | `available` \| `stopped` \| `not_found` | Ver tabela abaixo |
| `services[].source` | `systemd` \| `process` \| `docker` \| `""` | Onde foi achado; vazio se indisponível |
| `services[].unit` | string | Unit systemd, quando houver |
| `services[].action` | string | **Texto pronto** com o que fazer (comandos Debian/Ubuntu). Vazio se disponível |
| `services[].status_changed_at` | date-time \| `null` | Última mudança de `status` |

Significado do `status`:

| `status` | Significado | Cor sugerida |
|---|---|---|
| `available` | Em execução | verde |
| `stopped` | Instalado, mas parado/desativado | âmbar |
| `not_found` | Não instalado (nem em container) | cinza/vermelho |

Erros: `400` id inválido, `401`, `403`, `404` servidor inexistente, `429`.

**Regras de exibição**

- `services` vazio **não é erro**: significa que o agente ainda não reportou. Mostre "Aguardando o agente…".
- `source: "docker"` indica container. Mostre um selo "via Docker".
- `action` é texto pronto; exiba em bloco de código com botão **Copiar**. Não monte comandos no front.
- A descoberta é atualizada pelo agente a cada ~1 minuto. Para o painel atualizar, faça polling a cada 30–60 s ou refaça a consulta ao receber um evento SSE de serviço.
- O front **não envia nada**: a descoberta é só leitura.

### Exemplo (TypeScript)

```ts
export type DiscoveryStatus = 'available' | 'stopped' | 'not_found';

export interface DiscoveryItem {
  key: string;
  name: string;
  available: boolean;
  status: DiscoveryStatus;
  source: '' | 'systemd' | 'process' | 'docker';
  unit: string;
  action: string;
  checked_at: string;
  status_changed_at: string | null;
}

export interface Discovery {
  summary: { total: number; available: number; unavailable: number };
  checked_at: string | null;
  services: DiscoveryItem[];
}

export async function getDiscovery(serverId: string): Promise<Discovery> {
  const res = await fetch(`/api/v1/servers/${serverId}/discovery`, { credentials: 'include' });
  if (!res.ok) throw new Error(`discovery: ${res.status}`);
  return (await res.json()).data;
}
```

### Tela sugerida (aba "Serviços" do servidor)

```
Serviços   8 disponíveis · 2 indisponíveis        atualizado há 20 s
┌────────────┐ ┌────────────┐ ┌────────────┐
│ ● SSH      │ │ ● Nginx    │ │ ● Redis    │
│ systemd    │ │ systemd    │ │ via Docker │
└────────────┘ └────────────┘ └────────────┘
┌──────────────────────────────────────────┐
│ ▲ systemd-timesyncd — não encontrado     │
│ O que fazer:                  [Copiar]   │
│ sudo apt install systemd-timesyncd ...   │
└──────────────────────────────────────────┘
```

---

## 4. Alertas e incidentes (nada novo no front)

A descoberta já está ligada ao sistema existente:

- Serviço que **já esteve disponível** e depois cai (`stopped` ou `not_found`) vira `status: "down"` em `GET /services`.
- A regra padrão **"Serviço indisponível"** (`service_down`, severidade crítica, 120 s para disparar, 60 s para recuperar) abre alerta e incidente e dispara as notificações (Telegram, SSE) como antes.
- Quando o serviço volta, o alerta e o incidente se resolvem sozinhos.

Portanto as telas de **alertas, incidentes e regras** não mudam. Se existir lista de regras com opção de tipo de serviço, basta tirar o filtro por tipo.

---

## 5. Checklist de implementação

1. [ ] Remover botão/tela/formulário de **criar, editar, excluir** serviço.
2. [ ] Remover o botão **"Verificar agora"** (`POST /services/{id}/check`).
3. [ ] Remover filtros e campos por tipo (`http`, `tcp`, `systemd`); manter filtro por `status` e `server_id`.
4. [ ] Tratar `service_type` como `"discovered"` nos tipos TypeScript.
5. [ ] Criar a aba **Serviços** do servidor com `GET /servers/{id}/discovery`: resumo, cartões por `status`, `source` e bloco `action` copiável.
6. [ ] Tratar estado vazio (`checked_at: null`) como "Aguardando o agente".
7. [ ] Manter a lista global `GET /services` como somente leitura, ocultando `target`/`config`/latência.
8. [ ] Atualizar a tela por polling (30–60 s) ou SSE.
9. [ ] Tratar `404` de rotas antigas durante a transição (versões em cache do front).

---

## 6. Ordem de atualização em produção

Atualize **API e agente juntos** (`deploy/update.sh`). Um agente antigo ainda tenta `POST /agent/services` e recebe `404`; isso só gera aviso no log, mas ele não envia a descoberta até ser atualizado, então a aba Serviços ficará em "Aguardando o agente" nesse servidor.
