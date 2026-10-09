#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: CONFIRM_RESTORE=YES scripts/restore.sh backups/aegisai-YYYYMMDD-HHMMSS.dump" >&2
  exit 2
fi

if [ "${CONFIRM_RESTORE:-}" != "YES" ]; then
  echo "Restore is destructive. Re-run with CONFIRM_RESTORE=YES after verifying the backup." >&2
  exit 2
fi

backup_file="$1"
checksum_file="${backup_file}.sha256"

if [ ! -f "$backup_file" ] || [ ! -f "$checksum_file" ]; then
  echo "Backup file and matching .sha256 file are both required." >&2
  exit 2
fi

sha256sum --check "$checksum_file"
docker compose exec -T postgres sh -c \
  'pg_restore --clean --if-exists --no-owner --no-privileges --exit-on-error --single-transaction -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < "$backup_file"
echo "Restore completed. Run make config-check and curl http://127.0.0.1:8000/ready."
