#!/usr/bin/env bash
# Instala o agente num servidor monitorado.
#   sudo ./install-agent.sh <caminho-do-binario> <https://api.exemplo.com> <token>
# O token é lido da entrada se for "-" (evita aparecer no histórico do shell).
set -euo pipefail

BIN="${1:?uso: $0 <binario> <url-da-api> <token|->}"
URL="${2:?informe a URL da API (https://...)}"
TOKEN="${3:?informe o token (ou - para ler da entrada padrão)}"
[ "$(id -u)" -eq 0 ] || { echo "execute como root (sudo)"; exit 1; }
case "$URL" in https://*) ;; *) echo "use uma URL https:// (o token trafega no cabeçalho Authorization)"; exit 1;; esac
[ "$TOKEN" = "-" ] && { read -r -s -p "Token do agente: " TOKEN; echo; }
case "$TOKEN" in snt_*) ;; *) echo "token inválido (deve começar com snt_)"; exit 1;; esac

install -m 0755 "$BIN" /usr/local/bin/sentinela-agent
install -d -m 0700 /etc/sentinela
umask 077
printf '%s\n' "$TOKEN" > /etc/sentinela/agent-token
chmod 0600 /etc/sentinela/agent-token

SRC="$(dirname "$0")/sentinela-agent.service"
sed "s|https://sentinela.exemplo.com|$URL|" "$SRC" > /etc/systemd/system/sentinela-agent.service
systemctl daemon-reload
systemctl enable --now sentinela-agent
sleep 2
systemctl --no-pager --lines=5 status sentinela-agent || true
echo "Pronto. Logs: journalctl -u sentinela-agent -f"
