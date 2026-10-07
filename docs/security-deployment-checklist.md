# Security Deployment Checklist

AEGISAI is safe to run as a loopback-only local lab after the controls in this
repository are enabled. A public production deployment is a separate operational
decision: it needs the platform controls below as well as this application code.

## Attacker-minded controls implemented in the application

| Threat | What an attacker could try | Control now in AEGISAI |
|---|---|---|
| Forged access token | Use a public development JWT secret to mint an Admin token | Production rejects the known development secret, requires a unique JWT secret, and validates issuer plus audience. |
| Cross-service token replay | Present an AEGISAI token to another service sharing a signing key | Tokens include and validate the `aegisai-api` audience. |
| SSRF / internal scanning | Register a model URL such as a cloud metadata or private `172.*` host | Local endpoints are explicit; remote endpoints need an exact allowlist and public-IP resolution. |
| Evidence disclosure | Read database backups or tables containing prompts and model output | Production requires a Fernet encryption key for newly stored evidence. |
| Login guessing | Repeatedly submit password guesses | The API limits failed attempts per client/IP and email in each API process. |
| Request flooding | Send huge/chunked bodies to consume memory | API and nginx body limits reject requests above 64 KiB by default. |
| Model-resource exhaustion | Run many long requests or ask for unlimited output | Model calls have a timeout, output-token cap, and bounded per-process concurrency. |
| Host-header abuse | Send an untrusted `Host` header to influence generated links or proxy behavior | Trusted Host validation is enabled and production requires an explicit host list. |
| Browser token persistence | Recover a token from durable browser storage after a shared-device session | The dashboard uses session storage, so the token is cleared when the browser session ends. |
| Unreviewed audit changes | Modify an audit row and hide it in normal views | The audit chain is verified through `GET /audit-logs/verify`; PostgreSQL chain writes are serialized per organization. |
| Information disclosure | Fingerprint nginx/API docs and inspect oversized error responses | nginx hides its version, production disables API docs by default, and error responses are bounded. |

## Required production configuration

Set these values in your deployment secret manager, not Git or a frontend build:

```env
AEGISAI_ENVIRONMENT=production
AEGISAI_AUTH_REQUIRED=true
AEGISAI_JWT_SECRET=<unique-32-plus-character-secret>
AEGISAI_EVIDENCE_ENCRYPTION_KEY=<valid-fernet-key>
AEGISAI_CORS_ORIGINS=https://aegisai.example.com
AEGISAI_TRUSTED_HOSTS=api.aegisai.example.com,127.0.0.1,localhost
AEGISAI_EXPOSE_API_DOCS=false
AEGISAI_MODEL_MAX_CONCURRENCY=2
AEGISAI_MODEL_TIMEOUT_SECONDS=60
AEGISAI_MODEL_MAX_OUTPUT_TOKENS=512
```

Use an exact `AEGISAI_LOCAL_MODEL_ENDPOINTS` value for a controlled local/WSL
Ollama host. Enable `AEGISAI_ALLOW_REMOTE_OLLAMA` only when every remote endpoint
is explicitly approved and owned by your organization.

## Required platform controls before internet exposure

These cannot be honestly solved only by source code or Docker Compose:

1. Terminate TLS at a maintained reverse proxy/load balancer; redirect HTTP to HTTPS
   and set HSTS only after the HTTPS domain is verified.
2. Keep Postgres private, encrypt its storage/backups, test restores, and restrict
   production database administration.
3. Use a managed secret store and rotate the JWT/encryption/bootstrap secrets. Never
   use the example values.
4. Replace the process-local login limit with an edge or Redis-backed limit when
   running more than one API replica.
5. Move campaign execution into isolated workers with egress controls, quotas, and
   a queue before accepting untrusted users or high-volume work.
6. Add MFA/SSO for administrators, central log retention, monitoring, alerting, and
   an incident-response owner.
7. Encrypt or securely delete **existing** plaintext evidence before loading real
   customer prompts. The current encryption applies to new records after the key is set.
8. Run dependency/container scans in CI, an authenticated API authorization test, and
   an independent penetration test before a customer-facing launch.

## Release decision

**Local/portfolio lab:** approved after `make restart`, `make lint`, `make test`, and
the health/dashboard checks pass.

**Internet-facing production:** not approved until every platform control above is
implemented, tested in staging, and reviewed by the person accountable for the
deployment. No application can guarantee that every vulnerability is eliminated;
the goal is layered controls, monitoring, and a recoverable incident process.
