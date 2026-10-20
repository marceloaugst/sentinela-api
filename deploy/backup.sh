#!/usr/bin/env bash
# Backup lógico do PostgreSQL (formato custom, restaurável com pg_restore), com rotação.
#   ./backup.sh                   -> /var/backups/sentinela/sentinela-AAAAMMDD-HHMMSS.dump
# Agende (cron do root):  17 3 * * *  /opt/sentinela/deploy/backup.sh >> /var/log/sentinela-backup.log 2>&1
# Guarde cópias FORA do servidor (o backup contém tokens de canais cifrados, mas não a SECRETS_KEY: guarde-a à parte).
set -euo pipefail
DIR="${BACKUP_DIR:-/var/backups/sentinela}"
KEEP_DAYS="${KEEP_DAYS:-14}"
COMPOSE="${COMPOSE:-docker compose -f /opt/sentinela/deploy/compose.yaml --env-file /opt/sentinela/.env}"
umask 077
mkdir -p "$DIR"
OUT="$DIR/sentinela-$(date +%Y%m%d-%H%M%S).dump"
$COMPOSE exec -T postgres pg_dump -U sentinela -d sentinela -Fc --no-owner > "$OUT"
[ -s "$OUT" ] || { echo "backup vazio"; rm -f "$OUT"; exit 1; }
# valida que o arquivo é legível pelo pg_restore
$COMPOSE exec -T postgres pg_restore --list < "$OUT" > /dev/null
find "$DIR" -name 'sentinela-*.dump' -mtime +"$KEEP_DAYS" -delete
echo "$(date -Is) backup ok: $OUT ($(du -h "$OUT" | cut -f1))"
