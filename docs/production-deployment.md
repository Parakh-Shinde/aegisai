# Production deployment runbook

This runbook adds an HTTPS edge to the existing Docker Compose stack. It is
intended for a host you administer (a hardened VM or dedicated server) with a
public DNS name. It does not create cloud resources or make a free hosting tier
suitable for confidential customer data.

## Important budget and data boundary

A public, real-user deployment that stores security evidence needs durable storage,
tested backups, access control, incident response, and a host whose data-handling
terms meet your obligations. Many free app/database tiers sleep, expire, limit
retention, or do not provide restorable backups. Do not put customer prompts,
security findings, incident evidence, tokens, or confidential logs into a free
demo unless those limitations have been explicitly reviewed and accepted.

The `compose.production.yaml` overlay is for self-managed Docker hosting. It
does not make the hosting free. If the budget is strictly zero, use a public
demo with synthetic data only and keep confidential data in a controlled local
environment until an appropriate production host is available.

## Architecture

- Caddy is the only service published on public ports 80 and 443 and obtains
  HTTPS certificates for the configured domain.
- Caddy routes `/api/*` to the API after removing the `/api` prefix; all other
  paths go to the static frontend. The frontend uses the same-origin `/api`
  base path, avoiding a public API port and cross-origin browser calls.
- The API, worker, PostgreSQL, and Redis are not directly published on public
  interfaces. Existing API/frontend host ports remain loopback-bound for local
  diagnostics only.
- PostgreSQL/Redis and Caddy certificate state use named Docker volumes. Named
  volumes are not a backup strategy; arrange encrypted off-host backups and
  test restoration before storing real data.

## Prerequisites

1. A Docker Engine/Compose host that you administer, with a firewall allowing
   inbound TCP 80/443 (and optional UDP 443), and a DNS A/AAAA record pointing
   the domain to that host.
2. An email address for certificate notices.
3. A protected secret store or a local `.env.production` file readable only by
   the deployment operator.
4. A data-retention, backup, restore, monitoring, and incident-response plan.

Do not run a public launch from a laptop or workstation containing personal data
unless you deliberately intend to operate and maintain a public server.

## Prepare secrets on the deployment host

Copy the example and restrict permissions:

```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Edit `.env.production` locally on the deployment host. Never paste its contents
into a chat, issue, pull request, build log, or public repository.

Generate independent values. Use `openssl rand -hex 32` for the PostgreSQL
password, JWT secret, gateway token, tool-runner token, and bootstrap token.
Generate each separately; do not reuse values. For each Fernet key, run this
stdlib-only Python command separately:

```bash
python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
```

Put one generated value in each corresponding variable:
`AEGISAI_EVIDENCE_ENCRYPTION_KEY` and `AEGISAI_MFA_ENCRYPTION_KEY`.
Do not regenerate encryption keys after data has been encrypted unless you have
implemented and tested a key-rotation/migration procedure.

Set `AEGISAI_DOMAIN` to the real hostname and `ACME_EMAIL` to an address you
control. The example values are placeholders and must not be used for a launch.
Keep remote model/application targets disabled unless you have an exact approved
allowlist and have reviewed where prompts and evidence are sent.

## Preflight (no services started)

From the repository root, validate merged configuration without printing it:

```bash
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml config --quiet
```

Run the existing release checks before deployment:

```bash
make lint
make test
make config-check
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml run --rm --no-deps api \
  python -m scripts.verify_runtime_config
```

The final command validates the effective production settings inside the backend
container's Python environment. Review
any failure; do not bypass checks to get a green result. Review the rendered
Compose security properties privately if needed, but do not publish its full
output because it can contain resolved secret values.

## Before first public start

- Confirm DNS resolves to the intended host and the firewall exposes only 80/443.
- Confirm the server's disks and backups have appropriate encryption and access.
- Verify no old plaintext evidence needs migration before real data is imported.
  Follow the evidence migration procedure and test it on a restorable copy first.
- Confirm the initial administrator bootstrap endpoint and one-time bootstrap token
  process with the application tests. Treat the bootstrap token as a high-value
  secret. After account creation, rotate it to a new random unused value because
  the production Compose overlay requires a non-empty bootstrap token.
- Verify MFA enrollment and recovery, tenant isolation, API-token scopes, login
  rate limits, CORS/trusted-host checks, and unauthorized API responses.
- Review model endpoint allowlists and ensure no sensitive data is sent to a
  provider without an approved privacy/data-processing agreement.
- Ensure PostgreSQL and Redis are not reachable from the public internet.

Only after these checks pass should the operator start the stack:

```bash
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml up --build -d
```

Then verify status and health without dumping environment values:

```bash
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml ps

curl --fail --silent --show-error https://YOUR_REAL_DOMAIN/healthz
curl --fail --silent --show-error https://YOUR_REAL_DOMAIN/api/health
```

Replace `YOUR_REAL_DOMAIN` with the actual hostname. The first check is served by
the frontend edge; the second is routed to the API. Verify that `/docs` and
`/openapi.json` are not publicly exposed and that unauthenticated protected
API requests are rejected.

## Operational gates before accepting confidential data

- Perform and record an encrypted off-host database backup and a restore drill.
- Configure monitoring, alerting, log retention, incident ownership, and a patch
  schedule for the host and images.
- Scan dependencies and built images; close critical/high findings or document
  a risk acceptance before launch.
- Run an independent authenticated API and tenant-isolation security review.
- Set data deletion/retention rules and document the evidence encryption-key
  recovery process.
- Confirm actual provider terms, data residency, and breach-notification
  obligations. A free-tier label does not satisfy these requirements.

If any gate is not met, keep the deployment in synthetic-data demo mode.
