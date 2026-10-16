# Staging Runbook

This runbook deploys AEGISAI to a host you administer using the HTTPS Caddy
overlay. It is intended for **controlled staging with synthetic or approved test
data**, not as approval to accept customer data or launch a public SaaS.

## 1. Confirm the staging host

Before starting, confirm that you control the host and DNS name, TCP ports 80
and 443 can reach it, Docker Engine/Compose are supported, and the host firewall
does not expose PostgreSQL, Redis, or the API directly. The base Compose file
binds the API and frontend diagnostic ports to loopback; Caddy is the public
entry point when the production overlay is enabled.

If you do not have a staging host and DNS name yet, stop at preflight. Do not
deploy to a personal workstation or expose the stack directly to the internet.

## 2. Create a protected staging environment file

On the staging host:

```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Edit `.env.production` locally. Never commit or paste it into chat, logs,
issues, or pull requests. Replace **every** example value with an independently
generated secret. Use `openssl rand -hex 32` separately for the database
password, JWT secret, agent gateway token, tool-runner token, and bootstrap
token. Generate two independent Fernet keys for evidence and MFA encryption
using:

```bash
python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
```

Set `AEGISAI_DOMAIN` to the real staging DNS name and `ACME_EMAIL` to an
address you control. Do not use the example domain or any `REPLACE_...` value.
The production overlay configures same-origin routing, so the frontend API base
is `/api`; do not change it to a separate API hostname unless the proxy and
CORS design are deliberately changed and reviewed.

Keep remote model/application targets disabled unless the provider, data
handling terms, and exact endpoint allowlist have been reviewed. Do not send
confidential prompts or evidence to public/free model endpoints.

## 3. Run preflight checks before starting services

From a clean checkout of the merged commit on the staging host:

```bash
make lint
make test
make release-gate
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml config --quiet
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml run --build --rm --no-deps api \
  python scripts/verify_runtime_config.py
```

These checks should all pass. The configuration validator reports only safe
summary fields, not secret values. Do not publish the rendered Compose output,
because resolved configuration can contain secrets. Do not bypass a failing
gate to force deployment.

## 4. Backups and first start

Before importing any existing evidence, take a backup and test restoration in a
separate disposable environment. Keep encrypted off-host copies; a Docker named
volume is not a backup plan. If migrating an existing local database, follow
the evidence encryption and restore procedures before allowing real data.

Once preflight is green and the operator has confirmed DNS, firewall, secrets,
and backups:

```bash
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml up --build -d
docker compose --env-file .env.production \
  -f compose.yaml -f compose.production.yaml ps
curl --fail --silent --show-error https://YOUR_STAGING_DOMAIN/healthz
curl --fail --silent --show-error https://YOUR_STAGING_DOMAIN/api/health
```

Replace `YOUR_STAGING_DOMAIN` with the configured host. Confirm the API
readiness endpoint is healthy, migrations completed, and worker jobs execute.
Verify unauthenticated protected API requests are rejected and `/docs` and
`/openapi.json` are not publicly exposed. Complete an authenticated smoke
test, run a small synthetic-data campaign, verify the audit chain, and record
the results.

Immediately after creating the initial administrator, rotate the bootstrap
token to a new unique value and redeploy the API/worker. Keep MFA enabled for
administrative accounts and retain the independent MFA encryption key securely.

## 5. Staging exit criteria

Do not promote beyond controlled staging until all of these are verified:

- CI and local backend/frontend tests, lint, runtime configuration, and release
  gate pass on the exact deployed commit.
- TLS and hostname checks pass; only ports 80/443 are externally reachable.
- Authentication, role checks, MFA, token revocation, and organization isolation
  have been tested with distinct accounts.
- PostgreSQL backup and a restore drill have succeeded; backups are encrypted
  off-host and access-controlled.
- Monitoring, alerting, log retention, incident ownership, patching, and data
  retention/deletion procedures are documented.
- Remote model and live-application targets remain disabled unless explicitly
  allowlisted and approved; workers and tool runners have reviewed egress limits.
- An independent authenticated security review is complete before any real
  customer data or internet-facing production use.

A green CI run is necessary but does not replace host validation, a restore
drill, or an authenticated security review.
