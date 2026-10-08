# Staging Runbook

This runbook deploys AEGISAI as a controlled staging environment. It keeps the
Compose ports loopback-only; a separately managed TLS reverse proxy may be
placed in front of it after the hostname and certificate are verified.

## 1. Set staging configuration

Copy `.env.example` to `.env` on the staging host. Do not commit `.env`.
Set at least the following values, replacing every placeholder with a secret
from the deployment secret manager:

```env
POSTGRES_PASSWORD=<unique-database-password>
AEGISAI_ENVIRONMENT=production
AEGISAI_AUTH_REQUIRED=true
VITE_AUTH_REQUIRED=true
AEGISAI_ASYNC_CAMPAIGNS=true
VITE_ASYNC_CAMPAIGNS=true
AEGISAI_JWT_SECRET=<unique-32-plus-character-secret>
AEGISAI_EVIDENCE_ENCRYPTION_KEY=<valid-fernet-key>
AEGISAI_BOOTSTRAP_TOKEN=<one-time-bootstrap-secret>
AEGISAI_CORS_ORIGINS=https://staging.example.com
AEGISAI_TRUSTED_HOSTS=staging.example.com,127.0.0.1,localhost
AEGISAI_EXPOSE_API_DOCS=false
AEGISAI_REDIS_URL=redis://redis:6379/0
```

Set `VITE_API_BASE_URL` to the TLS API URL exposed by the reverse proxy, for
example `https://api-staging.example.com`. Add that dashboard URL to
`AEGISAI_CORS_ORIGINS` and its API host name to `AEGISAI_TRUSTED_HOSTS`.

Use a private network or managed TLS Redis service outside Compose. The bundled
Redis service is suitable only when it stays on the private Compose network.

## 2. Start and validate

```bash
make doctor
make restart
docker compose ps
curl --fail http://127.0.0.1:8000/health
docker compose logs --tail=100 worker
```

Expected services are `postgres`, `redis`, `api`, `worker`, and `web`. The API
and web ports must remain bound to `127.0.0.1` unless a reviewed network design
changes that intentionally.

Sign in with the bootstrapped Administrator account, run a basic campaign, and
confirm that the dashboard changes from “Campaign queued” to completed. Check
the worker log for a successful job and confirm `/audit-logs/verify` reports a
valid chain.

## 3. Protect existing data and recovery

Before adding customer data, encrypt historical plaintext evidence once:

```bash
make encrypt-evidence
make backup
```

Store the generated PostgreSQL backup outside the staging host using encrypted
storage, and regularly test restoration in a separate disposable environment.

## 4. Release gate

Do not expose this stack directly to the internet. Before promotion beyond
controlled staging, complete the platform controls in
`security-deployment-checklist.md`: TLS/HSTS, managed secrets, private and
encrypted backups, monitoring/alerting, administrator MFA or SSO, isolated
egress-controlled workers, and an independent penetration test.
