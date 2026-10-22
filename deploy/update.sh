#!/usr/bin/env bash
# Atualiza uma instalação EXISTENTE do Sentinela (API + ClickHouse + agente local) a partir deste repositório.
#
#   sudo ./deploy/update.sh                  # atualiza tudo e ativa o envio de logs que existirem nesta máquina
#   sudo ./deploy/update.sh --dry-run        # só mostra o que faria
#   sudo ./deploy/update.sh --no-agent       # só a API/ClickHouse
#   sudo ./deploy/update.sh --logs nginx,ufw # escolhe as fontes de log (padrão: as que existem; "none" desliga)
#
# Ordem (pensada para ter volta):
#   1. checagens  2. backup (banco, código atual, binário e unit do agente)  3. copia o código novo (preserva o .env)
#   4. sobe API + ClickHouse e espera ficar saudável (se falhar, restaura o código anterior)
#   5. atualiza o agente (se falhar, restaura o binário e o unit anteriores)  6. verificação
# Não mexe em Nginx, Postgres, Redis nem no token do agente. Dados e .env são preservados.
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${SENTINELA_DIR:-/opt/sentinela}"
BACKUP_ROOT="${BACKUP_ROOT:-/root/backups}"
UNIT=/etc/systemd/system/sentinela-agent.service
AGENT_BIN=/usr/local/bin/sentinela-agent

DRY_RUN=0; NO_AGENT=0; NO_BACKUP=0; LOGS=""; LOGS_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --no-agent) NO_AGENT=1; shift;;
    --skip-backup) NO_BACKUP=1; shift;;
    --logs) LOGS="${2?}"; LOGS_SET=1; shift 2;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "opção desconhecida: $1" >&2; exit 2;;
  esac
done

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_bld=$'\e[1m'; c_off=$'\e[0m'
[ -t 1 ] || { c_red=; c_grn=; c_ylw=; c_bld=; c_off=; }
step() { printf '\n%s==> %s%s\n' "$c_bld" "$*" "$c_off"; }
ok()   { printf '  %s✔%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '  %s!%s %s\n' "$c_ylw" "$c_off" "$*"; }
die()  { printf '\n%sERRO:%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
compose() { docker compose -f "$APP_DIR/deploy/compose.yaml" --env-file "$APP_DIR/.env" "$@"; }
# (sem "cmd | grep -q": com pipefail dá falso negativo por SIGPIPE; a saída vai para uma variável)
has_text() { [[ "$1" == *"$2"* ]]; }

# ---------------------------------------------------------------- 1. checagens
step "1/6 Checagens"
[ "$DRY_RUN" = 1 ] || [ "$(id -u)" -eq 0 ] || die "execute como root (sudo)"
have docker && docker compose version >/dev/null 2>&1 || die "docker compose não encontrado"
[ -f "$REPO/deploy/compose.yaml" ] && [ -f "$REPO/cmd/api/main.go" ] || die "execute de dentro do repositório do Sentinela"
[ -f "$APP_DIR/deploy/compose.yaml" ] || die "instalação não encontrada em $APP_DIR (defina SENTINELA_DIR)"
[ "$DRY_RUN" = 1 ] || [ -r "$APP_DIR/.env" ] || die "não consigo ler $APP_DIR/.env (rode como root)"
[ "$(cd "$APP_DIR" && pwd -P)" != "$REPO" ] || die "o repositório e a instalação são a mesma pasta"
PORT="$(sed -n 's/^API_HOST_PORT=\(.*\)$/\1/p' "$APP_DIR/.env" 2>/dev/null | tail -1 || true)"; PORT="${PORT:-8088}"
ok "repositório: $REPO"; ok "instalação: $APP_DIR (API em 127.0.0.1:$PORT)"

AGENT_OK=1
if [ "$NO_AGENT" = 1 ]; then AGENT_OK=0
elif [ ! -f "$UNIT" ]; then AGENT_OK=0; warn "agente não instalado neste servidor ($UNIT): use deploy/setup-local-agent.sh; seguindo só com a API"
elif ! have go; then AGENT_OK=0; warn "Go não encontrado: o agente NÃO será atualizado (instale o Go ou compile em outra máquina)"; fi

if [ "$LOGS_SET" = 0 ]; then
  [ -e /var/log/nginx/access.log ] && LOGS="nginx"
  [ -e /var/log/fail2ban.log ] && LOGS="${LOGS:+$LOGS,}fail2ban"
  [ -e /var/log/ufw.log ] && LOGS="${LOGS:+$LOGS,}ufw"
fi
[ "$LOGS" = "none" ] && LOGS=""
[ "$AGENT_OK" = 1 ] && ok "logs a enviar: ${LOGS:-nenhum}"

# ---------------------------------------------------------------- 2. backup
STAMP="$(date +%Y%m%d-%H%M%S)"; BK="$BACKUP_ROOT/update-$STAMP"
step "2/6 Backup em $BK"
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] pg_dump (backup.sh), cópia do código atual, do binário e do unit do agente"
else
  umask 077; mkdir -p "$BK"
  if [ "$NO_BACKUP" = 0 ]; then
    if BACKUP_DIR="$BK" COMPOSE="docker compose -f $APP_DIR/deploy/compose.yaml --env-file $APP_DIR/.env" bash "$REPO/deploy/backup.sh" >/dev/null; then
      ok "banco salvo e validado"
    else die "backup do banco falhou (nada foi alterado). Use --skip-backup para ignorar, por sua conta e risco"; fi
  else warn "backup do banco ignorado (--skip-backup)"; fi
  tar -C "$APP_DIR" --exclude=bin -czf "$BK/app-before.tgz" . && ok "código atual salvo (app-before.tgz, inclui .env: proteja)"
  if [ -f "$UNIT" ]; then cp -p "$UNIT" "$BK/sentinela-agent.service" && ok "unit do agente salvo"; fi
  if [ -f "$AGENT_BIN" ]; then cp -p "$AGENT_BIN" "$BK/sentinela-agent" && ok "binário do agente salvo"; fi
fi

# ---------------------------------------------------------------- 3. código novo
step "3/6 Copiando o código novo para $APP_DIR (o .env é preservado)"
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] tar do repositório (sem .git/.env/bin) -> $APP_DIR; garante CLICKHOUSE_PASSWORD no .env"
else
  # o tar só sobrescreve: arquivos removidos do repositório (ex.: pacotes apagados) ficariam no destino e quebrariam o build
  for d in cmd internal migrations api; do rm -rf "${APP_DIR:?}/$d"; done
  tar -C "$REPO" --exclude=.git --exclude=.env --exclude=bin -cf - . | tar -C "$APP_DIR" -xf -
  ok "código copiado"
  if ! grep -q '^CLICKHOUSE_PASSWORD=.' "$APP_DIR/.env"; then
    echo "CLICKHOUSE_PASSWORD=$(openssl rand -hex 24)" >> "$APP_DIR/.env"; ok "CLICKHOUSE_PASSWORD gerada no .env"
  fi
fi

# ---------------------------------------------------------------- 4. API + ClickHouse
rollback_app() {
  warn "restaurando o código anterior e subindo a API antiga"
  tar -C "$APP_DIR" -xzf "$BK/app-before.tgz" && compose up -d --build api || true
}
step "4/6 Subindo API e ClickHouse"
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] docker compose up -d --build ; esperaria http://127.0.0.1:$PORT/readyz"
else
  compose up -d --build || { compose logs --tail 30 api || true; rollback_app; die "docker compose falhou; código anterior restaurado"; }
  ready=0
  for _ in $(seq 1 90); do
    if curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then compose logs --tail 40 api || true; rollback_app; die "a API não ficou saudável em 90 s; código anterior restaurado (backup em $BK)"; fi
  ok "API saudável"
  # a tabela existir é a prova de que a API conseguiu criar o esquema (a mensagem no log pode já ter rolado)
  stored=0
  for _ in $(seq 1 60); do
    ex="$(compose exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -q "EXISTS TABLE sentinela.logs"' 2>/dev/null || true)"
    if [ "${ex//[$' \t\r\n']/}" = 1 ]; then stored=1; break; fi
    sleep 1
  done
  if [ "$stored" = 1 ]; then ok "ClickHouse pronto (tabela sentinela.logs existe)"
  else warn "o armazenamento de logs ainda não ficou pronto; a API tenta de novo a cada 30 s (veja: docker compose logs clickhouse api)"; fi
fi

# ---------------------------------------------------------------- 5. agente
rollback_agent() {
  warn "restaurando o agente anterior"
  if [ -f "$BK/sentinela-agent" ]; then install -m 0755 "$BK/sentinela-agent" "$AGENT_BIN"; fi
  if [ -f "$BK/sentinela-agent.service" ]; then install -m 0644 "$BK/sentinela-agent.service" "$UNIT"; fi
  systemctl daemon-reload; systemctl restart sentinela-agent || true
}
step "5/6 Agente"
if [ "$AGENT_OK" = 0 ]; then
  echo "  (pulado)"
elif [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] compilaria o agente, manteria a URL atual do unit, aplicaria o unit novo (grupo adm, StateDirectory, SENTINELA_LOGS=${LOGS:-nenhum}) e reiniciaria"
else
  API_URL="$(sed -n 's/^Environment=SENTINELA_API_URL=\(.*\)$/\1/p' "$UNIT" | head -1 || true)"
  [ -n "$API_URL" ] || die "não achei SENTINELA_API_URL em $UNIT (API já atualizada; o agente não foi alterado)"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  (cd "$REPO" && go build -buildvcs=false -o "$TMP/sentinela-agent" ./cmd/agent) || die "falha ao compilar o agente (API já atualizada; o agente não foi alterado)"
  ok "agente compilado"
  sed -e "s|^Environment=SENTINELA_API_URL=.*|Environment=SENTINELA_API_URL=$API_URL|" \
      -e "s|^#Environment=SENTINELA_LOGS=.*|${LOGS:+Environment=SENTINELA_LOGS=$LOGS}|" \
      "$REPO/deploy/sentinela-agent.service" > "$TMP/unit"
  install -m 0755 "$TMP/sentinela-agent" "$AGENT_BIN.new" && mv -f "$AGENT_BIN.new" "$AGENT_BIN"
  install -m 0644 "$TMP/unit" "$UNIT"
  systemctl daemon-reload
  systemctl restart sentinela-agent
  sleep 6
  state="$(systemctl is-active sentinela-agent || true)"
  if [ "$state" != active ]; then
    journalctl -u sentinela-agent -n 15 --no-pager || true
    rollback_agent; die "o agente não subiu; versão anterior restaurada"
  fi
  ok "agente ativo ($API_URL)"
  jr="$(journalctl -u sentinela-agent -n 30 --no-pager 2>&1 || true)"
  if [ -n "$LOGS" ]; then
    if has_text "$jr" "envio de logs ativo"; then ok "envio de logs ativo ($LOGS)"
    else warn "não vi 'envio de logs ativo' no journal: veja journalctl -u sentinela-agent -n 30"; fi
    if has_text "$jr" "ermission denied"; then warn "o agente não consegue ler algum log (permissão): confira o grupo adm nos arquivos de /var/log"; fi
  fi
fi

# ---------------------------------------------------------------- 6. verificação
step "6/6 Verificação"
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] contaria as linhas já gravadas no ClickHouse"
elif [ "$AGENT_OK" = 1 ] && [ -n "$LOGS" ]; then
  sleep 15
  rows="$(compose exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" -q "SELECT source, count() FROM sentinela.logs GROUP BY source ORDER BY source FORMAT TSV"' 2>&1 || true)"
  if [ -n "$rows" ] && ! has_text "$rows" "Exception"; then
    ok "logs já gravados no ClickHouse:"; printf '%s\n' "$rows" | sed 's/^/      /'
  else
    warn "ainda sem linhas (o agente lê só o que for escrito DEPOIS de iniciar; o ufw costuma gerar em segundos). Confira em alguns minutos: GET /api/v1/logs/stats"
  fi
else
  echo "  (nada a verificar)"
fi

printf '\n%sPronto.%s Backup desta atualização: %s\n' "$c_bld" "$c_off" "$BK"
cat <<MSG
Desfazer manualmente:
  código:  tar -C $APP_DIR -xzf $BK/app-before.tgz && docker compose -f $APP_DIR/deploy/compose.yaml --env-file $APP_DIR/.env up -d --build api
  agente:  install -m 0755 $BK/sentinela-agent $AGENT_BIN && install -m 0644 $BK/sentinela-agent.service $UNIT && systemctl daemon-reload && systemctl restart sentinela-agent
MSG
