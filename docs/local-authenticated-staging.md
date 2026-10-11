# Local Authenticated Staging

This runbook converts an existing **local development lab** into a private,
authenticated staging environment without deleting its PostgreSQL evidence.

It is for a computer you control. It does not make the stack internet-ready.
Keep Docker Compose ports bound to `127.0.0.1`.

## What the migration does

Development mode creates `local-analyst@aegisai.local` automatically using a
known development password. When local authentication is enabled, AEGISAI's
one-time staging bootstrap:

1. disables that development-only account;
2. creates your chosen real Admin account in the same organization;
3. preserves existing campaigns, evidence, and release-approval records;
4. returns a short-lived Admin JWT;
5. records the event in the tamper-evident audit chain.

The endpoint works only when all of these are true:

- `AEGISAI_ENVIRONMENT=development`
- `AEGISAI_AUTH_REQUIRED=true`
- `AEGISAI_ALLOW_LOCAL_STAGING_BOOTSTRAP=true`
- a valid `AEGISAI_BOOTSTRAP_TOKEN` is supplied

It is explicitly rejected in production.

## 1. Back up first

```bash
make backup
```

## 2. Update `.env`

Generate secrets locally, then place the output in `.env`—never in Git:

```bash
openssl rand -hex 32
openssl rand -hex 32
```

Set these values:

```env
AEGISAI_ENVIRONMENT=development
AEGISAI_AUTH_REQUIRED=true
VITE_AUTH_REQUIRED=true
AEGISAI_JWT_SECRET=<first-generated-secret>
AEGISAI_BOOTSTRAP_TOKEN=<second-generated-secret>
AEGISAI_ALLOW_LOCAL_STAGING_BOOTSTRAP=true
```

Restart the stack:

```bash
make restart
```

## 3. Create the first real Admin

Choose a long unique password and run this once, replacing the placeholders:

```bash
curl --fail --request POST \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: <bootstrap-secret>" \
  --data '{"email":"admin@example.local","password":"<long-unique-password>"}' \
  http://127.0.0.1:8000/auth/local-staging-bootstrap | jq
```

Immediately change the final configuration value to prevent another bootstrap:

```env
AEGISAI_ALLOW_LOCAL_STAGING_BOOTSTRAP=false
AEGISAI_BOOTSTRAP_TOKEN=
```

Then restart again:

```bash
make restart
```

Sign in at `http://127.0.0.1:5173` with the new Admin account.

## 4. Create a separate Analyst

Log in as the Admin and create an analyst through the API. Store the Admin JWT
only in your current terminal session:

```bash
ADMIN_TOKEN=$(curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data '{"email":"admin@example.local","password":"<long-unique-password>"}' \
  http://127.0.0.1:8000/auth/login | jq -r .access_token)

curl --fail --request POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"email":"analyst@example.local","password":"<another-long-unique-password>","role":"security_analyst"}' \
  http://127.0.0.1:8000/auth/users | jq
```

For the release-approval demonstration, sign in as the Analyst to request a
release approval, then sign back in as the Admin to approve it. A requester
cannot approve their own request.

## Safety boundary

This is an authenticated local staging lab, not public production. Before any
internet exposure, use the production runbook: HTTPS, a real domain, managed
secrets, MFA/SSO, external backups, monitoring/alerting, egress controls, and
an independent security review.
