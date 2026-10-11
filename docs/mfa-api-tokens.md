# MFA and scoped API tokens

AEGISAI v29 adds two distinct identity controls:

- **TOTP multi-factor authentication (MFA)** for people using the dashboard.
- **Scoped API tokens** for automation such as CI jobs and approved integrations.

They are not interchangeable. API tokens cannot manage users, change passwords,
enroll MFA, or approve a release.

## Before enabling MFA

Set an independent encryption key before anyone enrolls an authenticator. In
production this is mandatory; in development AEGISAI derives a local fallback
from the JWT secret only to keep an isolated lab usable.

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the generated value in `.env`:

```dotenv
AEGISAI_MFA_ENCRYPTION_KEY=paste-the-new-value-here
```

Then restart the stack. Do not rotate this key without a planned MFA reset:
existing encrypted authenticator secrets cannot be recovered with a new key.

## Enroll MFA

Sign in, open **Identity**, and enter your current password under **Enable MFA**.
AEGISAI displays a one-time secret for 15 minutes. Add it to an authenticator
application as a time-based one-time password, then submit the displayed
six-digit code. The plaintext secret is never retained or shown again.

After MFA is enabled, sign-in requires email, password, and the six-digit
authenticator code. Enabling or disabling MFA revokes other browser sessions.

If an authenticated user loses the authenticator, a different organization
Admin can use **Reset MFA** for that account. This is an audited recovery path
and also revokes existing sessions.

## Create an API token

Only an interactive Admin session can create or revoke an automation token.
Go to **Identity → Create scoped API token** and copy the value immediately.
AEGISAI stores only its SHA-256 hash and can never show the plaintext again.

Scopes:

| Scope | Permits |
| --- | --- |
| `read` | Read-only authenticated API routes. |
| `write` | Analyst-level test, model, and evaluation actions; includes `read`. |

Tokens are intentionally limited to `viewer` or `security_analyst` roles.
They cannot perform Admin identity operations or make final release decisions.

Example read request:

```bash
export AEGISAI_TOKEN='agt_copy-the-token-once'
curl --fail \
  -H "Authorization: Bearer $AEGISAI_TOKEN" \
  http://127.0.0.1:8000/ai-systems/
```

Keep tokens in a CI secret store or environment variable, never in source code,
the frontend, shell history, screenshots, or Git commits. Revoke a token in the
Identity page as soon as it is no longer needed or is suspected exposed.

## Release approval separation

Release requests now require a **Security Analyst**. A separate **Admin** must
make the final decision and AEGISAI verifies that the evidence digest has not
changed. This provides role separation for the local pilot; independent human
ownership still matters in a real production organization.
