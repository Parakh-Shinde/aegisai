#!/usr/bin/env sh
set -eu

backup_dir="${AEGISAI_BACKUP_DIR:-backups}"
timestamp="$(date +%Y%m%d-%H%M%S)"
backup_file="${backup_dir}/aegisai-${timestamp}.dump"

mkdir -p "$backup_dir"
docker compose exec -T postgres sh -c \
  'pg_dump --format=custom --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  > "$backup_file"
sha256sum "$backup_file" > "${backup_file}.sha256"

printf 'Database backup saved: %s\nChecksum saved: %s.sha256\n' \
  "$backup_file" "$backup_file"
