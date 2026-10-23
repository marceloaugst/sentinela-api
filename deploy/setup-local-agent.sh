#!/usr/bin/env bash
# Cadastra ESTA máquina no Sentinela e instala o agente como serviço (systemd), falando com a API por localhost.
#   ./deploy/setup-local-agent.sh
# Pede apenas a senha do painel (sem eco). Variáveis opcionais: ADMIN_EMAIL, API_PORT, SERVER_NAME,
# AGENT_LOGS (fontes de log a enviar; padrão: as que existem nesta máquina entre nginx, fail2ban e ufw; "none" desliga),
# AGENT_DOCKER=yes (deixa o agente listar/iniciar/reiniciar containers: dá acesso ao socket do Docker, que equivale a root).
set -euo pipefail

ADMIN_EMAIL="${ADMIN_EMAIL:-marcelo.augsd@gmail.com}"
API_PORT="${API_PORT:-8088}"
SERVER_NAME="${SERVER_NAME:-vps-principal}"
API_BASE="http://127.0.0.1:${API_PORT}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${AGENT_LOGS+x}" ]; then
  AGENT_LOGS=""
  [ -e /var/log/nginx/access.log ] && AGENT_LOGS="nginx"
  [ -e /var/log/fail2ban.log ] && AGENT_LOGS="${AGENT_LOGS:+$AGENT_LOGS,}fail2ban"
  [ -e /var/log/ufw.log ] && AGENT_LOGS="${AGENT_LOGS:+$AGENT_LOGS,}ufw"
fi
[ "$AGENT_LOGS" = "none" ] && AGENT_LOGS=""

for cmd in go curl jq sudo; do
  command -v "$cmd" >/dev/null || { echo "faltando: $cmd"; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
umask 077

echo "==> Compilando o agente"
(cd "$ROOT" && go build -buildvcs=false -o "$TMP/sentinela-agent" ./cmd/agent)

read -r -s -p "Senha do painel (${ADMIN_EMAIL}): " PW; echo

echo "==> Login"
LOGIN="$(jq -n --arg e "$ADMIN_EMAIL" --arg p "$PW" '{email:$e,password:$p}' \
  | curl -sS -c "$TMP/cookies" -X POST "$API_BASE/api/v1/auth/login" -H 'Content-Type: application/json' -d @-)"
unset PW
CSRF="$(jq -r '.data.csrf_token // empty' <<<"$LOGIN")"
[ -n "$CSRF" ] || { echo "login falhou: $(jq -r '.error.message // .' <<<"$LOGIN")"; exit 1; }

echo "==> Cadastrando o servidor '${SERVER_NAME}'"
SRV="$(curl -sS -b "$TMP/cookies" -X POST "$API_BASE/api/v1/servers" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d "$(jq -n --arg n "$SERVER_NAME" --arg h "$(hostname)" '{name:$n,hostname:$h}')")"
SID="$(jq -r '.data.id // empty' <<<"$SRV")"
[ -n "$SID" ] || { echo "cadastro falhou: $(jq -r '.error.message // .' <<<"$SRV")"; exit 1; }

echo "==> Gerando o token do agente"
CRED="$(curl -sS -b "$TMP/cookies" -X POST "$API_BASE/api/v1/servers/$SID/agent-credentials" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{"replace":true}')"
TOKEN="$(jq -r '.data.token // empty' <<<"$CRED")"
case "$TOKEN" in snt_*) ;; *) echo "token inválido: $(jq -r '.error.message // .' <<<"$CRED")"; exit 1;; esac
printf '%s\n' "$TOKEN" > "$TMP/agent-token"
unset TOKEN

echo "==> Instalando o serviço (pede sudo)"
sudo install -m 0755 "$TMP/sentinela-agent" /usr/local/bin/sentinela-agent
sudo install -d -m 0700 /etc/sentinela
sudo install -m 0600 "$TMP/agent-token" /etc/sentinela/agent-token
sed -e "s|https://sentinela.exemplo.com|${API_BASE}|" \
    -e "s|^#Environment=SENTINELA_LOGS=.*|${AGENT_LOGS:+Environment=SENTINELA_LOGS=${AGENT_LOGS}}|" "$ROOT/deploy/sentinela-agent.service" \
  | sudo tee /etc/systemd/system/sentinela-agent.service >/dev/null
if [ -d /etc/polkit-1/rules.d ]; then # permite ao agente iniciar/parar/reiniciar só as unidades do catálogo
  sudo install -m 0644 "$ROOT/deploy/50-sentinela-agent.rules" /etc/polkit-1/rules.d/50-sentinela-agent.rules
else
  echo "aviso: polkit não encontrado; o painel não conseguirá iniciar/parar/reiniciar serviços (apt install polkitd)"
fi
if [ "${AGENT_DOCKER:-}" = yes ] && getent group docker >/dev/null; then
  sudo install -d -m 0755 /etc/systemd/system/sentinela-agent.service.d
  printf '[Service]\nSupplementaryGroups=docker\n' | sudo tee /etc/systemd/system/sentinela-agent.service.d/docker.conf >/dev/null
  echo "Agente com acesso ao Docker (grupo docker)."
fi
sudo systemctl daemon-reload
sudo systemctl enable --now sentinela-agent
sleep 3
sudo systemctl --no-pager --lines=8 status sentinela-agent || true

echo
echo "Logs enviados: ${AGENT_LOGS:-nenhum}"
echo "Pronto. Servidor ${SID}. Logs: journalctl -u sentinela-agent -f"
