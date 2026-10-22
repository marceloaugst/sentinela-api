#!/usr/bin/env bash
# Sobe o Sentinela neste servidor, publica a API no IP da máquina (HTTPS) e REMOVE o server-monitor.
#
#   sudo ./deploy/setup-server.sh --admin-email voce@exemplo.com            # interativo (pede a senha)
#   sudo ./deploy/setup-server.sh --dry-run                                  # só mostra o que faria (não exige root)
#
# Ordem (pensada para nunca deixar a máquina sem serviço):
#   1. checagens  2. backup do server-monitor (verificado)  3. confirmação
#   4. sobe o Sentinela em 127.0.0.1 (sem conflito de porta) e espera ficar saudável
#   5. troca o site do Nginx (testa; se falhar, devolve o antigo e PARA sem remover nada)
#   6. remove o server-monitor  7. primeiro administrador  8. resumo
#
# O Postgres e o Redis desta máquina são COMPARTILHADOS com outros apps: o script nunca os derruba.
# O banco "server_monitor" só é apagado com --purge-data (o backup é feito de qualquer forma).
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
set -euo pipefail

# ---------------------------------------------------------------- configuração
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${SENTINELA_DIR:-/opt/sentinela}"
TLS_DIR=/etc/sentinela/tls
BACKUP_ROOT=/root/backups
LOCAL_PORT="${SENTINELA_LOCAL_PORT:-8088}"                       # a API escuta só em 127.0.0.1:8088 (o Nginx publica na 443)
NGINX_SITE=/etc/nginx/sites-available/sentinela.conf

DRY_RUN=0; ASSUME_YES=0; PURGE_DATA=0; SKIP_DB_BACKUP=0; KEEP_SM=0; APP_ONLY=0
IP="${SERVER_IP:-}"; ADMIN_EMAIL="${ADMIN_EMAIL:-}"; ADMIN_NAME="${ADMIN_NAME:-Administrador}"
SM_SOURCE="${SM_SOURCE:-}"

usage() {
  cat <<'EOF'
Uso: sudo setup-server.sh [opções]
  --admin-email E     e-mail do primeiro administrador (obrigatório se ainda não houver usuários)
  --admin-name N      nome do administrador (padrão: Administrador)
                      a senha vem de SENTINELA_ADMIN_PASSWORD, é pedida (oculta) ou, sem terminal, é gerada e exibida uma vez
  --ip A.B.C.D        IP público (padrão: detectado)
  --sm-source DIR     pasta com o código do server-monitor a apagar (padrão: ~/server-monitor do usuário do sudo)
  --app-only          ENSAIO SEGURO: sobe só o Sentinela em 127.0.0.1 (sem Nginx, sem root, sem remover nada)
  --keep-server-monitor   não remove o server-monitor (só sobe o Sentinela; a porta 443 precisa estar livre)
  --purge-data        também APAGA o banco "server_monitor" do Postgres compartilhado (após o backup)
  --skip-db-backup    não faz o pg_dump do banco do server-monitor (não recomendado)
  --yes               não pede confirmação (para automação)
  --dry-run           mostra o plano e as ações, sem alterar nada
EOF
}
while [ $# -gt 0 ]; do
  case "$1" in
    --admin-email) ADMIN_EMAIL="${2:?}"; shift 2;;
    --admin-name) ADMIN_NAME="${2:?}"; shift 2;;
    --ip) IP="${2:?}"; shift 2;;
    --sm-source) SM_SOURCE="${2:?}"; shift 2;;
    --app-only) APP_ONLY=1; KEEP_SM=1; shift;;
    --keep-server-monitor) KEEP_SM=1; shift;;
    --purge-data) PURGE_DATA=1; shift;;
    --skip-db-backup) SKIP_DB_BACKUP=1; shift;;
    --yes|-y) ASSUME_YES=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "opção desconhecida: $1" >&2; usage; exit 2;;
  esac
done

# ---------------------------------------------------------------- utilidades
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_bld=$'\e[1m'; c_off=$'\e[0m'
[ -t 1 ] || { c_red=; c_grn=; c_ylw=; c_bld=; c_off=; }
step() { printf '\n%s==> %s%s\n' "$c_bld" "$*" "$c_off"; }
ok()   { printf '  %s✔%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '  %s!%s %s\n' "$c_ylw" "$c_off" "$*"; }
die()  { printf '\n%sERRO:%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }
# run: executa, ou só imprime no --dry-run
run() { if [ "$DRY_RUN" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }
# ATENÇÃO: com "set -o pipefail", "cmd | grep -q" dá falso negativo quando o grep sai cedo e o cmd recebe SIGPIPE.
# Por isso nada aqui usa "| grep -q": a saída vai para uma variável e é testada sem pipe.
unit_exists() { local o; o="$(systemctl list-unit-files "$1.service" 2>/dev/null || true)"; [[ "$o" == *"$1.service"* ]]; }
db_exists() { local o; o="$(docker exec "$1" psql -U postgres -lqt 2>/dev/null || true)"; [[ $'\n'"$(printf '%s\n' "$o" | cut -d'|' -f1 | tr -d ' ')"$'\n' == *$'\nserver_monitor\n'* ]]; }
listening() { local o; o="$(ss -ltn "sport = :$1" 2>/dev/null || true)"; [[ "$o" == *LISTEN* ]]; }
compose() { docker compose -f "$APP_DIR/deploy/compose.yaml" --env-file "$APP_DIR/.env" "$@"; }

# ---------------------------------------------------------------- 1. checagens
step "1/8 Checagens"
if [ "$DRY_RUN" = 1 ]; then warn "modo --dry-run: nada será alterado"
elif [ "$APP_ONLY" = 1 ]; then warn "modo --app-only: só o Sentinela em 127.0.0.1:$LOCAL_PORT, em $APP_DIR (nada é removido)"
else [ "$(id -u)" -eq 0 ] || die "execute como root: sudo $0 ..."; fi
NEEDED="docker openssl curl tar"; [ "$APP_ONLY" = 1 ] || NEEDED="$NEEDED nginx systemctl"
for cmd in $NEEDED; do have "$cmd" || die "comando ausente: $cmd"; done
docker compose version >/dev/null 2>&1 || die "o plugin 'docker compose' não está instalado"
[ -f "$REPO/deploy/compose.yaml" ] && [ -f "$REPO/cmd/api/main.go" ] || die "execute este script de dentro do repositório do Sentinela (deploy/setup-server.sh)"

if [ -z "$IP" ]; then
  IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)"
fi
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "não consegui detectar o IP; informe com --ip A.B.C.D"
ok "IP do servidor: $IP"

SM_PRESENT=0
for u in server-monitor-api server-monitor-collector server-monitor-reverb; do
  unit_exists "$u" && SM_PRESENT=1
done
[ -d /opt/server-monitor ] && SM_PRESENT=1
[ -z "$SM_SOURCE" ] && [ -n "${SUDO_USER:-}" ] && SM_SOURCE="$(getent passwd "$SUDO_USER" | cut -d: -f6)/server-monitor"
[ -z "$SM_SOURCE" ] && SM_SOURCE="/home/claude/server-monitor"
SM_SOURCE_OK=0
if [ -d "$SM_SOURCE" ]; then
  # trava de segurança: só apaga se REALMENTE parecer o projeto server-monitor
  [ -f "$SM_SOURCE/deploy/install.sh" ] && [ -d "$SM_SOURCE/agent" ] && grep -q "server-monitor" "$SM_SOURCE/deploy/install.sh" \
    && SM_SOURCE_OK=1 || warn "$SM_SOURCE existe mas não parece o server-monitor: NÃO será apagada"
fi
[ "$SM_PRESENT" = 1 ] && ok "server-monitor encontrado (serviços/instalação)" || ok "server-monitor não está instalado (nada a remover)"

if [ "$KEEP_SM" = 1 ] && [ "$APP_ONLY" = 0 ] && [ -e /etc/nginx/sites-enabled/server-monitor-api.conf ]; then
  die "a porta 443 deste IP já é usada pelo site do server-monitor; não é possível manter os dois no mesmo IP:443. Rode sem --keep-server-monitor."
fi

# o contêiner Postgres que hospeda o banco do server-monitor (compartilhado com outros apps)
SM_PG=""
if [ "$SM_PRESENT" = 1 ] && [ "$KEEP_SM" = 0 ]; then
  for n in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    if db_exists "$n"; then SM_PG="$n"; break; fi
  done
  [ -n "$SM_PG" ] && ok "banco 'server_monitor' encontrado no contêiner '$SM_PG' (compartilhado: só esse banco é tocado)" \
                  || warn "banco 'server_monitor' não localizado; o backup do banco será pulado"
fi

# ---------------------------------------------------------------- plano e confirmação
step "Plano"
cat <<EOF
  SOBE:      Sentinela em $APP_DIR (API + PostgreSQL PRÓPRIO, sem porta publicada), escutando em 127.0.0.1:$LOCAL_PORT
  PUBLICA:   $([ "$APP_ONLY" = 1 ] && echo "nada (--app-only: apenas http://127.0.0.1:$LOCAL_PORT)" || echo "https://$IP/  (Nginx, TLS autoassinado para o IP em $TLS_DIR)")
EOF
if [ "$KEEP_SM" = 0 ] && { [ "$SM_PRESENT" = 1 ] || [ "$SM_SOURCE_OK" = 1 ]; }; then
  cat <<EOF
  REMOVE (server-monitor), depois de um backup verificado em $BACKUP_ROOT/server-monitor-<data>/:
     • serviços systemd: server-monitor-api, server-monitor-collector, server-monitor-reverb
     • /opt/server-monitor   /etc/server-monitor (config e certificado)   /usr/local/sbin/server-monitor-ctl
     • Nginx: site server-monitor-api.conf e snippet; fail2ban: filtro e jail do server-monitor
     • usuário do sistema 'monitor'
EOF
  [ "$SM_SOURCE_OK" = 1 ] && echo "     • código-fonte: $SM_SOURCE"
  if [ "$PURGE_DATA" = 1 ]; then echo "     • ${c_red}BANCO 'server_monitor'${c_off} no Postgres compartilhado (--purge-data)"; else echo "  PRESERVA:  o banco 'server_monitor' e o Redis (compartilhados). Use --purge-data para apagar o banco."; fi
  echo "  NÃO TOCA:  contêineres postgres/redis e os bancos app e atlas."
fi
if [ "$DRY_RUN" = 0 ] && [ "$KEEP_SM" = 0 ] && { [ "$SM_PRESENT" = 1 ] || [ "$SM_SOURCE_OK" = 1 ]; } && [ "$ASSUME_YES" = 0 ]; then
  [ -t 0 ] || die "sem terminal para confirmar; use --yes"
  printf '\n%sA remoção do server-monitor é IRREVERSÍVEL (exceto pelo backup).%s Digite REMOVER para continuar: ' "$c_red" "$c_off"
  read -r ans; [ "$ans" = "REMOVER" ] || die "cancelado (nada foi alterado)"
fi

# ---------------------------------------------------------------- 2. backup
BACKUP_DIR=""
if [ "$KEEP_SM" = 0 ] && { [ "$SM_PRESENT" = 1 ] || [ "$SM_SOURCE_OK" = 1 ]; }; then
  step "2/8 Backup do server-monitor"
  BACKUP_DIR="$BACKUP_ROOT/server-monitor-$(date +%Y%m%d-%H%M%S)"
  if [ "$DRY_RUN" = 1 ]; then
    echo "  [dry-run] criaria $BACKUP_DIR com: opt.tar.gz, etc.tar.gz, nginx.tar.gz, source.tar.gz, database.dump, SHA256SUMS"
  else
    umask 077; install -d -m 0700 "$BACKUP_ROOT" "$BACKUP_DIR"
    tarit() { # nome base alvos...
      local out="$BACKUP_DIR/$1.tar.gz"; shift
      local present=(); for t in "$@"; do [ -e "/$t" ] && present+=("$t"); done
      [ ${#present[@]} -gt 0 ] || return 0
      tar -C / -czf "$out" "${present[@]}" 2>/dev/null; tar -tzf "$out" >/dev/null || die "backup corrompido: $out"; ok "$(basename "$out")"
    }
    tarit opt opt/server-monitor
    tarit etc etc/server-monitor usr/local/sbin/server-monitor-ctl
    tarit nginx etc/nginx/sites-available/server-monitor-api.conf etc/nginx/snippets/server-monitor-proxy.conf \
               etc/fail2ban/filter.d/server-monitor-api.conf etc/fail2ban/jail.d/server-monitor-api.local \
               etc/systemd/system/server-monitor-api.service etc/systemd/system/server-monitor-collector.service etc/systemd/system/server-monitor-reverb.service
    if [ "$SM_SOURCE_OK" = 1 ]; then
      tar -C "$(dirname "$SM_SOURCE")" --exclude='node_modules' --exclude='vendor' -czf "$BACKUP_DIR/source.tar.gz" "$(basename "$SM_SOURCE")"
      tar -tzf "$BACKUP_DIR/source.tar.gz" >/dev/null || die "backup do código corrompido"; ok "source.tar.gz (sem vendor/node_modules)"
    fi
    if [ -n "$SM_PG" ] && [ "$SKIP_DB_BACKUP" = 0 ]; then
      docker exec "$SM_PG" pg_dump -U postgres -d server_monitor -Fc > "$BACKUP_DIR/database.dump" || die "pg_dump falhou"
      docker exec -i "$SM_PG" pg_restore --list < "$BACKUP_DIR/database.dump" >/dev/null || die "o dump do banco não é restaurável"
      ok "database.dump ($(du -h "$BACKUP_DIR/database.dump" | cut -f1), verificado com pg_restore --list)"
    elif [ "$SKIP_DB_BACKUP" = 1 ]; then warn "backup do banco pulado (--skip-db-backup)"; fi
    ( cd "$BACKUP_DIR" && sha256sum ./* > SHA256SUMS )
    umask 022
    ok "backup completo em $BACKUP_DIR (apenas root lê: contém segredos)"
  fi
else
  step "2/8 Backup — nada a fazer"
fi

# ---------------------------------------------------------------- 4. subir o Sentinela
step "3/8 Instalando o Sentinela em $APP_DIR"
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] copiaria o repositório para $APP_DIR e geraria $APP_DIR/.env (segredos aleatórios, chmod 600) se ainda não existir"
else
  install -d -m 0755 "$APP_DIR"
  tar -C "$REPO" --exclude=.git --exclude=.env --exclude=bin -cf - . | tar -C "$APP_DIR" -xf -
  if [ ! -f "$APP_DIR/.env" ]; then
    # NUNCA regenere depois: a senha do Postgres é fixada na criação do volume.
    umask 077
    {
      echo "APP_ENV=production"
      echo "API_HOST_PORT=$LOCAL_PORT"
      echo "TRUST_PROXY=true"
      echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
      echo "CLICKHOUSE_PASSWORD=$(openssl rand -hex 24)"
      echo "SECRETS_KEY=$(openssl rand -hex 32)"
      echo "METRICS_TOKEN=$(openssl rand -hex 24)"
      echo "ADMIN_API_KEY="
      echo "CORS_ALLOWED_ORIGINS="
    } > "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"; ok ".env criado com segredos aleatórios (chmod 600)"
  else
    ok ".env existente preservado"
  fi
  grep -q '^API_HOST_PORT=' "$APP_DIR/.env" || echo "API_HOST_PORT=$LOCAL_PORT" >> "$APP_DIR/.env"
  # instalações anteriores aos logs: o ClickHouse (novo volume) ganha uma senha própria
  grep -q '^CLICKHOUSE_PASSWORD=.' "$APP_DIR/.env" || echo "CLICKHOUSE_PASSWORD=$(openssl rand -hex 24)" >> "$APP_DIR/.env"
  PORT_IN_USE="$(ss -ltn "sport = :$LOCAL_PORT" 2>/dev/null | awk 'NR>1' | head -1)"
  RUNNING_API="$(compose ps --status running --services 2>/dev/null || true)"
  if [ -n "$PORT_IN_USE" ] && [[ "$RUNNING_API" != *api* ]]; then die "a porta $LOCAL_PORT já está em uso: $PORT_IN_USE"; fi
fi

step "4/8 Subindo os contêineres e esperando ficar saudável"
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] docker compose up -d --build ; aguardaria http://127.0.0.1:$LOCAL_PORT/readyz"
else
  compose up -d --build
  for i in $(seq 1 90); do curl -fsS "http://127.0.0.1:$LOCAL_PORT/readyz" >/dev/null 2>&1 && break; sleep 1; [ "$i" = 90 ] && { compose logs --tail 40 api; die "a API não ficou saudável em 90 s (o server-monitor NÃO foi alterado)"; }; done
  ok "API saudável em 127.0.0.1:$LOCAL_PORT (migrações aplicadas)"
fi

# ---------------------------------------------------------------- 5. Nginx + TLS no IP
if [ "$APP_ONLY" = 1 ]; then
  step "5/8 Nginx — pulado (--app-only)"
else
step "5/8 Publicando em https://$IP/ (Nginx + TLS autoassinado)"
make_cert() {
  install -d -m 0755 /etc/sentinela; install -d -m 0750 "$TLS_DIR"
  if [ -f "$TLS_DIR/server.crt" ] && openssl x509 -in "$TLS_DIR/server.crt" -noout -checkend $((30*86400)) >/dev/null 2>&1 \
     && [[ "$(openssl x509 -in "$TLS_DIR/server.crt" -noout -ext subjectAltName 2>/dev/null || true)" == *"IP Address:$IP"* ]]; then
    ok "certificado existente ainda é válido para $IP"; return
  fi
  ( umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" \
      -days 397 -subj "/CN=$IP/O=Sentinela" -addext "subjectAltName=IP:$IP" -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=serverAuth" 2>/dev/null )
  chmod 0644 "$TLS_DIR/server.crt"; chmod 0600 "$TLS_DIR/server.key"; ok "certificado gerado (397 dias)"
}
nginx_conf() {
  local http2_line="listen 443 ssl;"; local http2_dir="    http2 on;"
  # nginx >= 1.25.1 usa a diretiva http2 on; antes disso, o parâmetro no listen
  local v; v="$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9.]*\).*/\1/p')"
  if [ "$(printf '%s\n1.25.1\n' "$v" | sort -V | head -1)" != "1.25.1" ]; then http2_line="listen 443 ssl http2;"; http2_dir=""; fi
  cat <<EOF
# Gerado por setup-server.sh. API do Sentinela em https://$IP/ (certificado autoassinado para o IP).
limit_req_zone  \$binary_remote_addr zone=sentinela_login:10m rate=5r/s;
limit_req_zone  \$binary_remote_addr zone=sentinela_api:10m   rate=30r/s;
limit_conn_zone \$binary_remote_addr zone=sentinela_conn:10m;

server {
    listen 80;
    listen [::]:80;
    server_name $IP;
    return 301 https://\$host\$request_uri;
}

server {
    $http2_line
    listen [::]:443 ssl;
$http2_dir
    server_name $IP;

    ssl_certificate     $TLS_DIR/server.crt;
    ssl_certificate_key $TLS_DIR/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SentinelaTLS:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    server_tokens off;
    client_max_body_size 1m;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # A API usa Host (verificação de Origin/CSRF) e X-Real-IP (bloqueio de login por IP; TRUST_PROXY=true).
    proxy_http_version 1.1;
    proxy_set_header Host              \$host;
    proxy_set_header X-Real-IP         \$remote_addr;
    proxy_set_header X-Forwarded-For   \$remote_addr;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Connection        "";

    location = /api/v1/events {            # SSE: sem buffer, leitura longa
        proxy_pass http://127.0.0.1:$LOCAL_PORT;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        limit_conn sentinela_conn 20;
    }
    location = /api/v1/auth/login {        # login: limite estrito (Argon2id é caro)
        limit_req zone=sentinela_login burst=10 nodelay;
        proxy_pass http://127.0.0.1:$LOCAL_PORT;
    }
    location /api/ {
        limit_req zone=sentinela_api burst=100 nodelay;
        proxy_pass http://127.0.0.1:$LOCAL_PORT;
    }
    location = /healthz { proxy_pass http://127.0.0.1:$LOCAL_PORT; access_log off; }
    location = /readyz  { proxy_pass http://127.0.0.1:$LOCAL_PORT; access_log off; }
    location = /metrics {                  # só a própria máquina (e exige METRICS_TOKEN)
        allow 127.0.0.1;
        deny all;
        proxy_pass http://127.0.0.1:$LOCAL_PORT;
    }
    location = / {
        default_type application/json;
        return 200 '{"service":"sentinela-api","docs":"/api/v1"}';
    }
    location / { return 404; }
}
EOF
}

OLD_SITE_LINK=/etc/nginx/sites-enabled/server-monitor-api.conf
OLD_WAS_ENABLED=0; [ -e "$OLD_SITE_LINK" ] && OLD_WAS_ENABLED=1
NGINX_SWAPPED=0
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] geraria o certificado, gravaria $NGINX_SITE, desativaria o site do server-monitor, rodaria nginx -t e recarregaria"
  echo "  [dry-run] conteúdo do site (prévia):"; nginx_conf | sed 's/^/      /' | head -22; echo "      ..."
else
  make_cert
  nginx_conf > "$NGINX_SITE"; chmod 0644 "$NGINX_SITE"
  [ "$OLD_WAS_ENABLED" = 1 ] && rm -f "$OLD_SITE_LINK"        # libera a 443 (o arquivo original fica em sites-available até a etapa 6)
  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/sentinela.conf
  rollback_nginx() {
    rm -f /etc/nginx/sites-enabled/sentinela.conf
    [ "$OLD_WAS_ENABLED" = 1 ] && ln -sf /etc/nginx/sites-available/server-monitor-api.conf "$OLD_SITE_LINK"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  }
  NGX_ERR="$(nginx -t 2>&1 || true)"
  if ! nginx -t >/dev/null 2>&1; then
    printf '%s\n' "$NGX_ERR" >&2; rollback_nginx; die "configuração do Nginx inválida; site antigo restaurado. Nada foi removido."
  fi
  systemctl reload nginx; NGINX_SWAPPED=1
  sleep 1
  if ! curl -fsSk --resolve "$IP:443:127.0.0.1" "https://$IP/readyz" >/dev/null 2>&1; then
    rollback_nginx; die "o Sentinela não respondeu em https://$IP/readyz; site antigo restaurado. Nada foi removido."
  fi
  ok "https://$IP/ responde (readyz ok)"
  UFW_STATUS="$(ufw status 2>/dev/null || true)"
  if have ufw && [[ "$UFW_STATUS" == *"Status: active"* ]]; then
    ufw allow 443/tcp comment 'Sentinela HTTPS' >/dev/null && ufw allow 80/tcp comment 'Sentinela redirect' >/dev/null && ok "ufw: portas 80 e 443 liberadas"
  else warn "ufw inativo: se houver outro firewall (ou do provedor), libere a porta 443/tcp"; fi
fi
fi # fim do bloco "5/8" (não é --app-only)

# ---------------------------------------------------------------- 6. remover o server-monitor
if [ "$KEEP_SM" = 0 ] && { [ "$SM_PRESENT" = 1 ] || [ "$SM_SOURCE_OK" = 1 ]; }; then
  step "6/8 Removendo o server-monitor"
  for u in server-monitor-api server-monitor-collector server-monitor-reverb; do
    if unit_exists "$u"; then
      run systemctl disable --now "$u.service" 2>/dev/null || true
      run rm -f "/etc/systemd/system/$u.service"; [ "$DRY_RUN" = 1 ] || ok "serviço $u removido"
    fi
  done
  run systemctl daemon-reload
  run rm -f /etc/nginx/snippets/server-monitor-proxy.conf /etc/nginx/sites-available/server-monitor-api.conf "$OLD_SITE_LINK"
  if [ -e /etc/fail2ban/jail.d/server-monitor-api.local ] || [ -e /etc/fail2ban/filter.d/server-monitor-api.conf ]; then
    run rm -f /etc/fail2ban/jail.d/server-monitor-api.local /etc/fail2ban/filter.d/server-monitor-api.conf
    systemctl is-active --quiet fail2ban 2>/dev/null && run systemctl reload fail2ban 2>/dev/null || true
  fi
  run rm -rf /opt/server-monitor /etc/server-monitor
  run rm -f /usr/local/sbin/server-monitor-ctl
  if id monitor >/dev/null 2>&1; then
    run userdel monitor 2>/dev/null || warn "não consegui remover o usuário 'monitor' (ainda há processos dele?)"
  fi
  [ "$SM_SOURCE_OK" = 1 ] && run rm -rf "$SM_SOURCE"
  if [ "$PURGE_DATA" = 1 ]; then
    if [ -n "$SM_PG" ]; then
      if [ "$DRY_RUN" = 1 ]; then echo "  [dry-run] DROP DATABASE server_monitor (em $SM_PG)"; else
        docker exec "$SM_PG" psql -U postgres -c "DROP DATABASE IF EXISTS server_monitor WITH (FORCE)" >/dev/null && ok "banco server_monitor apagado (backup em $BACKUP_DIR/database.dump)"; fi
    fi
  else
    [ -n "$SM_PG" ] && warn "banco 'server_monitor' preservado em '$SM_PG' (apague depois com --purge-data ou: docker exec $SM_PG psql -U postgres -c 'DROP DATABASE server_monitor')"
  fi
  if [ "$DRY_RUN" = 0 ]; then
    systemctl is-active --quiet nginx && nginx -t >/dev/null 2>&1 && systemctl reload nginx
    listening 8080 || ok "porta 8080 liberada"
    ok "server-monitor removido"
  fi
else
  step "6/8 Remoção do server-monitor — nada a fazer"
fi

# ---------------------------------------------------------------- 7. primeiro administrador
step "7/8 Primeiro administrador"
GENERATED_PW=""
if [ "$DRY_RUN" = 1 ]; then
  echo "  [dry-run] se não houver usuários: create-admin --email ${ADMIN_EMAIL:-<--admin-email>} (senha por stdin: variável, prompt oculto ou gerada)"
else
  NUSERS="$(compose exec -T postgres psql -U sentinela -d sentinela -tAc 'select count(*) from users' 2>/dev/null | tr -d '[:space:]')"
  if [ "${NUSERS:-0}" != "0" ]; then
    ok "já existem $NUSERS usuário(s); nada a criar"
  else
    if [ -z "$ADMIN_EMAIL" ] && [ -t 0 ]; then read -r -p "  E-mail do administrador: " ADMIN_EMAIL; fi
    [ -n "$ADMIN_EMAIL" ] || die "informe --admin-email (o Sentinela já está no ar; rode de novo só com esse parâmetro)"
    PW="${SENTINELA_ADMIN_PASSWORD:-}"
    if [ -z "$PW" ] && [ -t 0 ]; then
      while :; do
        read -r -s -p "  Senha (12+ caracteres, não óbvia): " PW; echo; read -r -s -p "  Repita a senha: " PW2; echo
        [ "$PW" = "$PW2" ] && [ -n "$PW" ] && break; warn "as senhas não conferem"
      done
    elif [ -z "$PW" ]; then
      GENERATED_PW="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 24)"; PW="$GENERATED_PW"
    fi
    OUT="$(mktemp)"
    if printf '%s\n' "$PW" | compose run --rm -T api create-admin --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" >"$OUT" 2>&1; then
      rm -f "$OUT"; ok "administrador criado: $ADMIN_EMAIL"
    else
      cat "$OUT" >&2; rm -f "$OUT"; die "não foi possível criar o administrador (veja acima; a senha deve ter 12+ caracteres e não ser óbvia)"
    fi
    unset PW PW2
  fi
fi

# ---------------------------------------------------------------- 8. resumo
step "8/8 Pronto"
if [ "$DRY_RUN" = 1 ]; then
  echo "  (dry-run concluído: nada foi alterado)"; exit 0
fi
if [ "$APP_ONLY" = 1 ]; then
  echo "  Sentinela no ar em http://127.0.0.1:$LOCAL_PORT  (arquivos em $APP_DIR). Nada foi publicado nem removido."
  [ -n "$GENERATED_PW" ] && printf '  Senha gerada do administrador (aparece só agora): %s\n' "$GENERATED_PW"
  echo "  Para desfazer o ensaio: docker compose -f $APP_DIR/deploy/compose.yaml --env-file $APP_DIR/.env down -v && rm -rf $APP_DIR"
  exit 0
fi
FP="$(openssl x509 -in "$TLS_DIR/server.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
cat <<EOF

  ${c_bld}API:${c_off}        https://$IP/api/v1
  ${c_bld}Saúde:${c_off}      curl -k https://$IP/healthz     (readyz verifica o banco)
  ${c_bld}Login:${c_off}      POST https://$IP/api/v1/auth/login  {"email":"...","password":"..."}  → cookie de sessão + csrf_token
  ${c_bld}Arquivos:${c_off}   $APP_DIR (código e .env com os segredos — chmod 600)
  ${c_bld}Logs:${c_off}       docker compose -f $APP_DIR/deploy/compose.yaml --env-file $APP_DIR/.env logs -f api
  ${c_bld}Backup:${c_off}     ${BACKUP_DIR:-—}

  ${c_ylw}Certificado autoassinado:${c_off} o navegador/curl vai avisar. Para confiar nele:
     scp $IP:$TLS_DIR/server.crt .   e importe como autoridade confiável (ou use curl --cacert server.crt)
     impressão digital SHA-256: $FP
  Com um domínio, troque por Let's Encrypt (docs/deployment.md, seção 5): cookie, HSTS e CSRF já estão prontos.
EOF
if [ -n "$GENERATED_PW" ]; then
  printf '\n  %sSENHA DO ADMINISTRADOR (gerada; aparece só agora, troque no primeiro acesso):%s\n     %s\n' "$c_red" "$c_off" "$GENERATED_PW"
fi
cat <<EOF

  ${c_ylw}Atenção (fora do escopo deste script):${c_off} os contêineres 'postgres' (5432) e 'redis' (6379) desta máquina estão
  publicados em 0.0.0.0, ou seja, acessíveis pela internet se o firewall do provedor permitir. Considere
  restringi-los a 127.0.0.1 ou bloquear essas portas no firewall.
  Para monitorar ESTA máquina com o Sentinela: crie um servidor e use deploy/install-agent.sh.
EOF
