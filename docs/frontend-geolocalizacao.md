# Geolocalização de IPs no frontend — guia de implementação

Como mostrar **país, provedor e reputação (AbuseIPDB)** dos IPs nas telas de logs e como montar o painel **"ataques por país"**.
Os exemplos estão em TypeScript/React, mas a parte de API vale para qualquer framework.

> Pré-requisito: o `api()` do [`frontend-api.md`](frontend-api.md) e as telas de [`frontend-logs.md`](frontend-logs.md). Tudo aqui é **somente leitura** (sem CSRF). Contrato oficial: [`api/openapi.yaml`](../api/openapi.yaml) (`IPGeo`, `/logs`, `/logs/stats`, `/logs/countries`). Funcionamento no servidor: [`logs.md`](logs.md#geolocalização-dos-ips-abuseipdb).

## Sumário
1. [Como funciona](#1-como-funciona)
2. [Tipos TypeScript](#2-tipos-typescript)
3. [Onde o `geo` aparece](#3-onde-o-geo-aparece)
4. [Painel por país (`/logs/countries`)](#4-painel-por-país-logscountries)
5. [Exibindo bandeira, país e pontuação](#5-exibindo-bandeira-país-e-pontuação)
6. [Dados que chegam aos poucos](#6-dados-que-chegam-aos-poucos)
7. [Erros e casos especiais](#7-erros-e-casos-especiais)
8. [Segurança](#8-segurança)
9. [Checklist](#9-checklist)

---

## 1. Como funciona

```
GET /logs, /logs/stats, /logs/countries
        │
        ├─ ClickHouse: lê os logs (IPs e contagens)
        │
        └─ API: para os IPs da resposta consulta o cache (PostgreSQL, tabela ip_intel)
                 ├─ IP em cache e válido ──────────────► usa
                 ├─ IP novo/vencido ──► AbuseIPDB (até 20 por requisição, 4 s) ──► grava no cache
                 └─ IP privado/loopback ───────────────► { private: true }, sem consulta
```

Pontos que afetam o frontend:

- **Nada muda nas rotas existentes**: `geo` é um campo **novo e opcional**. Telas que não o conhecem continuam funcionando.
- A consulta ao AbuseIPDB acontece **na leitura**, não na ingestão do log. IPs que ninguém abriu no painel não gastam cota.
- O AbuseIPDB informa o **país** (código ISO), provedor e pontuação de abuso. **Não há latitude/longitude**: para mapa de pontos seria preciso outra fonte; para mapa coroplético (países coloridos) o código do país basta.
- O cache vale `IP_INTEL_CACHE_HOURS` (padrão 7 dias). A cota diária é `ABUSEIPDB_DAILY_LIMIT` (padrão 1000, plano gratuito).
- Sem `ABUSEIPDB_API_KEY` na API, só aparece o que já estava em cache (no começo, nada).

---

## 2. Tipos TypeScript

```ts
// logs/geo-types.ts
export interface IPGeo {
  private?: boolean;            // IP de rede interna/loopback: nenhum outro campo vem
  country_code?: string;        // ISO 3166-1 alfa-2, ex.: "CN"
  isp?: string;
  usage_type?: string;          // ex.: "Data Center/Web Hosting/Transit"
  domain?: string;
  abuse_score: number;          // 0-100 (confiança de abuso do AbuseIPDB)
  total_reports: number;
  is_tor?: boolean;
  last_reported_at?: string;    // ISO-8601 UTC
  fetched_at: string;           // quando foi consultado (cache)
}

// acrescente aos tipos de frontend-logs.md:
export interface LogRow /* ...campos existentes... */ {
  geo?: IPGeo;                  // ausente: sem ip, ou ainda não consultado
}

export interface TopIP /* ...campos existentes... */ {
  geo?: IPGeo;
}

// /logs/countries — atenção: chaves em camelCase (diferente do resto da API)
export type CountryMetric = 'events' | 'bans' | 'blocks' | 'http_errors';

export interface CountryStats {
  generatedAt: string;          // ISO-8601 UTC
  periodDays: number;
  metric: CountryMetric;
  total: number;                // soma de countries[].events + unknown.events
  countries: {
    code: string;               // "BR"
    name: string;               // "Brazil" (em inglês)
    events: number;             // contagem da métrica escolhida (o nome do campo é sempre "events")
    ips: number;                // IPs distintos
    avgScore: number;           // média por IP do abuse_score, 0-100
  }[];                          // ordenado por events, do maior para o menor
  unknown: { events: number; ips: number };
}
```

---

## 3. Onde o `geo` aparece

| Rota | Onde | Observação |
|---|---|---|
| `GET /logs` | cada item de `data[]` que tem `ip` | `geo` ao lado de `ip`, `fields`, `raw`... |
| `GET /logs/stats` | cada item de `top_ips[]` | só os 10 IPs mais ativos |
| `GET /logs/countries` | agregado por país | não há `geo` por IP aqui |

Exemplo (`GET /api/v1/logs?source=fail2ban&type=ban`):

```json
{
  "data": [{
    "time": "2026-10-29T14:02:11Z",
    "server_id": "0b0d…",
    "source": "fail2ban", "type": "ban", "severity": "warning",
    "ip": "203.0.113.9",
    "fields": { "jail": "sshd" },
    "geo": {
      "country_code": "CN",
      "isp": "Example ISP",
      "usage_type": "Data Center/Web Hosting/Transit",
      "abuse_score": 87,
      "total_reports": 42,
      "last_reported_at": "2026-10-28T10:00:00Z",
      "fetched_at": "2026-10-29T14:05:00Z"
    }
  }],
  "meta": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
}
```

Para a mesma lista, o IP `10.0.0.5` viria com `"geo": { "private": true, "abuse_score": 0, "total_reports": 0, "fetched_at": "0001-01-01T00:00:00Z" }`. **Ignore `abuse_score`/`fetched_at` quando `private` for `true`.**

---

## 4. Painel por país (`/logs/countries`)

`GET /api/v1/logs/countries` — papel `viewer`+.

| Parâmetro | Padrão | Observação |
|---|---|---|
| `days` | `7` | 1 a 31 |
| `metric` | `events` | `events` (tudo exceto unban/allow), `bans`, `blocks` (firewall), `http_errors` (nginx ≥ 400) |
| `server_id` | todos | UUID |

Resposta (dentro do envelope `{ "data": ... }`):

```json
{
  "generatedAt": "2026-10-29T14:20:00Z",
  "periodDays": 7,
  "metric": "events",
  "total": 1842,
  "countries": [
    { "code": "BR", "name": "Brazil", "events": 912, "ips": 48, "avgScore": 34 },
    { "code": "US", "name": "United States", "events": 403, "ips": 61, "avgScore": 71 },
    { "code": "CN", "name": "China", "events": 287, "ips": 39, "avgScore": 88 }
  ],
  "unknown": { "events": 240, "ips": 33 }
}
```

Regras que importam para a tela:

- `total = soma(countries[].events) + unknown.events`. Use `total` como 100% nos percentuais e **mostre `unknown`** como uma linha "Sem país" (ou uma nota), senão a soma não fecha.
- `unknown` reúne: IPs privados, IPs ainda não consultados (ver seção 6) e eventos de IPs fora dos 1000 mais ativos do período.
- `name` vem em **inglês**. Para exibir em português, ignore-o e use `Intl.DisplayNames` com `code` (seção 5).
- A rota considera só os 1000 IPs mais ativos; é o suficiente para ranking, mas não é uma contagem exata de "IPs distintos" do período todo.

```ts
// logs/api.ts
export async function fetchCountries(opts: { days?: number; metric?: CountryMetric; server_id?: string } = {}) {
  const r = await api('/logs/countries', { query: clean(opts) });
  return r.data as CountryStats;
}
```

---

## 5. Exibindo bandeira, país e pontuação

### País em português e bandeira (sem biblioteca)

```ts
const regionNames = new Intl.DisplayNames(['pt-BR'], { type: 'region' });

export function countryName(code?: string) {
  return code ? regionNames.of(code) ?? code : '—';
}

// "BR" → 🇧🇷 (emoji de bandeira a partir de dois indicadores regionais)
export function flag(code?: string) {
  if (!code || code.length !== 2) return '🏳️';
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)));
}
```

> Emoji de bandeira **não aparece no Windows** (vira as letras "BR"). Se o painel é usado em Windows, prefira um conjunto de SVGs (ex.: `flag-icons`) com `country_code` em minúsculas.

### Célula de IP em tabelas

```tsx
export function IpCell({ ip, geo }: { ip?: string; geo?: IPGeo }) {
  if (!ip) return <span>—</span>;
  if (geo?.private) return <span>{ip} <small>(rede interna)</small></span>;
  return (
    <span title={geo ? `${geo.isp ?? ''} · ${geo.usage_type ?? ''}` : 'país ainda não consultado'}>
      {geo?.country_code ? `${flag(geo.country_code)} ` : ''}{ip}
      {geo && <ScoreBadge score={geo.abuse_score} />}
      {geo?.is_tor && <small> Tor</small>}
    </span>
  );
}
```

### Faixas sugeridas para `abuse_score` / `avgScore`

| Pontuação | Leitura | Cor sugerida |
|---|---|---|
| 0–24 | baixo risco | verde |
| 25–74 | suspeito | amarelo |
| 75–100 | muito provável abuso | vermelho |

```tsx
export function ScoreBadge({ score }: { score: number }) {
  const level = score >= 75 ? 'high' : score >= 25 ? 'mid' : 'low';
  return <span className={`score score-${level}`}> {score}</span>;
}
```

Não dependa só da cor: mostre o número (acessibilidade).

### Filtro por país no frontend

A API **não filtra logs por país** (o país não está no ClickHouse). Para "ver os logs da China", o caminho é: pegar os IPs do país e filtrar por `ip` (um por vez), ou filtrar a página já carregada pelo `geo.country_code`. Se esse filtro for importante, peça ao backend uma rota própria.

---

## 6. Dados que chegam aos poucos

A API consulta o AbuseIPDB de forma **gradual**: no máximo **20 IPs novos por requisição** (e 4 s de rede). Consequências:

- Na **primeira** abertura de uma lista com muitos IPs novos, parte dos itens vem **sem `geo`**. Isso significa *"ainda não consultado"*, não *"sem dados"*.
- Na **próxima** requisição (recarga, paginação, polling) os IPs seguintes são preenchidos. IPs já consultados vêm instantaneamente do cache.
- No `/logs/countries`, o `unknown` começa grande e **diminui** a cada recarga. É esperado.

Recomendações:

1. **Não mostre "país desconhecido" definitivo** para `geo` ausente; use um estado neutro (`—` ou um esqueleto discreto).
2. Se a tela depende de `geo` (painel por país), refaça a busca uma ou duas vezes enquanto `unknown.ips` > 0 e a tela estiver aberta:

```ts
// refaz até 3 vezes, a cada 5 s, enquanto houver IPs sem país
export function useCountries(opts: Parameters<typeof fetchCountries>[0]) {
  const [data, setData] = useState<CountryStats>();
  useEffect(() => {
    let alive = true, tries = 0;
    const load = async () => {
      const d = await fetchCountries(opts);
      if (!alive) return;
      setData(d);
      if (d.unknown.ips > 0 && ++tries < 3) setTimeout(load, 5000);
    };
    load();
    return () => { alive = false; };
  }, [JSON.stringify(opts)]);
  return data;
}
```

3. Evite *polling* agressivo: cada recarga com IPs novos consome cota diária. O polling normal da lista de logs (ver `frontend-logs.md`, seção 7) já é suficiente.

---

## 7. Erros e casos especiais

| Situação | O que o frontend vê | O que fazer |
|---|---|---|
| `ABUSEIPDB_API_KEY` não configurada | `geo` ausente em tudo (até existir cache) | Exibir normalmente sem país; `countries` pode vir vazio com tudo em `unknown` |
| Cota diária esgotada / 429 do AbuseIPDB | `geo` só nos IPs já em cache | Igual ao caso acima; volta a funcionar às 00:00 UTC |
| AbuseIPDB fora do ar | Nada quebra; IP fica sem `geo` | Tratar como "ainda não consultado" |
| Log sem `ip` (ex.: nginx error sem cliente) | Sem `geo` | Mostrar `—` |
| IP privado | `geo.private = true` | Mostrar "rede interna"; não exibir pontuação |
| `GET /logs/countries?days=99` ou `metric=x` | `422` com os campos inválidos | Limitar o seletor às opções válidas |
| ClickHouse indisponível | `503 LOGS_UNAVAILABLE` | Mesmo tratamento das demais telas de logs |

A falha na geolocalização **nunca** devolve erro nas rotas de logs: o pior caso é a resposta vir sem `geo`.

---

## 8. Segurança

- `isp`, `domain` e `usage_type` vêm de **terceiros** (AbuseIPDB). Renderize sempre como **texto** (JSX escapa por padrão; nunca use `dangerouslySetInnerHTML` nem `innerHTML`). Não transforme `domain` em link clicável.
- O `ip` e o resto do log já são dados controlados por quem ataca (ver `frontend-logs.md`, seção 9).
- Não chame o AbuseIPDB a partir do navegador: a chave fica só no servidor.

---

## 9. Checklist

- [ ] Tipos `IPGeo` e `CountryStats` adicionados; `geo` tratado como **opcional**.
- [ ] Célula de IP usa `geo.country_code` e mostra "rede interna" quando `geo.private`.
- [ ] `abuse_score` com número **e** cor; ignorado quando `private`.
- [ ] Nome do país via `Intl.DisplayNames` (pt-BR) a partir de `code`, não de `name`.
- [ ] Bandeira com fallback para Windows (SVG) se necessário.
- [ ] Painel por país mostra a linha **"Sem país"** com `unknown` e usa `total` como 100%.
- [ ] `geo` ausente tratado como "ainda não consultado" (nada de "desconhecido" definitivo).
- [ ] Painel por país refaz a busca algumas vezes enquanto `unknown.ips > 0`.
- [ ] Seletor de `days` limitado a 1–31 e `metric` aos 4 valores.
- [ ] Textos de `isp`/`domain` renderizados como texto puro.
