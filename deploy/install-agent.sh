#!/usr/bin/env bash
# Instala o agente num servidor monitorado.
#   sudo ./install-agent.sh <caminho-do-binario> <https://api.exemplo.com> <token> [--docker]
# --docker: deixa o agente listar/iniciar/reiniciar containers. Dá acesso ao socket do Docker, que equivale a root no servidor.
# O token é lido da entrada se for "-" (evita aparecer no histórico do shell).
set -euo pipefail

BIN="${1:?uso: $0 <binario> <url-da-api> <token|->}"
URL="${2:?informe a URL da API (https://...)}"
TOKEN="${3:?informe o token (ou - para ler da entrada padrão)}"
DOCKER_ACCESS="${4:-}"
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
# Permissão (polkit) para o agente iniciar/parar/reiniciar só as unidades do catálogo, a pedido do painel.
if [ -d /etc/polkit-1/rules.d ]; then
  install -m 0644 "$(dirname "$0")/50-sentinela-agent.rules" /etc/polkit-1/rules.d/50-sentinela-agent.rules
else
  echo "aviso: polkit não encontrado; o painel não conseguirá iniciar/parar/reiniciar serviços (apt install polkitd)"
fi
DROPIN=/etc/systemd/system/sentinela-agent.service.d/docker.conf
if [ "$DOCKER_ACCESS" = "--docker" ]; then
  if getent group docker >/dev/null; then
    install -d -m 0755 "$(dirname "$DROPIN")"
    printf '[Service]\nSupplementaryGroups=docker\n' > "$DROPIN"
    echo "agente com acesso ao Docker (grupo docker). Atenção: quem controla o agente controla o servidor."
  else
    echo "aviso: grupo docker não existe (Docker não instalado); seguindo sem acesso ao Docker"
  fi
fi
systemctl daemon-reload
systemctl enable --now sentinela-agent
sleep 2
systemctl --no-pager --lines=5 status sentinela-agent || true
echo "Pronto. Logs: journalctl -u sentinela-agent -f"
