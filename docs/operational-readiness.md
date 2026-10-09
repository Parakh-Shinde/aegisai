# Operational Readiness

This guide covers the operational controls included in AEGISAI v0.6. It is
designed for the local lab and controlled staging environments described in
the security deployment checklist. It does not make a public Internet-facing
deployment safe by itself.

## Validate configuration before starting

Run this after editing `.env` and before promoting a configuration:

```bash
make doctor
make config-check
```

`config-check` validates the effective application settings without printing
secrets. Production mode rejects SQLite, disabled authentication, weak JWT
secrets, missing evidence encryption, wildcard CORS or trusted hosts, and a
missing Redis/async campaign configuration.

## Liveness and readiness

The API exposes two different checks:

```bash
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/ready
```

`/health` means the API process is running. `/ready` additionally checks
PostgreSQL and, when async campaigns are enabled, Redis. A dependency outage
returns HTTP 503 without exposing internal error details.

## Backup and recovery

Create a compressed PostgreSQL backup and SHA-256 checksum:

```bash
make backup
```

Verify a backup before moving it to encrypted storage or using it for recovery:

```bash
make verify-backup BACKUP=backups/aegisai-YYYYMMDD-HHMMSS.dump
```

Restore replaces the current database. First stop users and campaigns, verify
the backup, and restore only into the intended environment:

```bash
make restore BACKUP=backups/aegisai-YYYYMMDD-HHMMSS.dump CONFIRM_RESTORE=YES
```

The explicit confirmation protects against an accidental destructive restore.
Test restores in a disposable local or staging stack before relying on backups.

## Audit evidence

Administrators can verify the organization audit chain and export up to 10,000
records. The CSV exporter neutralizes spreadsheet formulas in user-controlled
fields and sends `Cache-Control: no-store`.

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  -o aegisai-audit-logs.csv \
  http://127.0.0.1:8000/audit-logs/export
```

Use the same authenticated administrator session for
`GET /audit-logs/verify`. Store exported evidence and backups in encrypted
storage with access limited to the relevant organization.

## Container limits

Compose places memory, CPU, and process-count limits on the API, worker, web,
PostgreSQL, and Redis services. They reduce the blast radius of runaway work
in the local stack; adjust them only after measuring normal workload usage.

## GitHub merge protection

In GitHub, open **Settings → Rules → Rulesets** (or Branch protection) and
create a rule for `main` that requires the green `CI` workflow before merging.
Keep direct pushes restricted once you begin working with collaborators. This
is a repository control, not a replacement for reviewing the change itself.
