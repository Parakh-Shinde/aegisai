#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: scripts/verify_backup.sh backups/aegisai-YYYYMMDD-HHMMSS.dump" >&2
  exit 2
fi

backup_file="$1"
checksum_file="${backup_file}.sha256"

if [ ! -f "$backup_file" ] || [ ! -f "$checksum_file" ]; then
  echo "Backup file and matching .sha256 file are both required." >&2
  exit 2
fi

sha256sum --check "$checksum_file"
docker compose exec -T postgres pg_restore --list < "$backup_file" > /dev/null
echo "Backup is readable by PostgreSQL."
