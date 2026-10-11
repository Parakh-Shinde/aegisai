# Identity Operations

AEGISAI v28 adds a controlled account-lifecycle layer for authenticated
deployments. It is designed for normal operator use, so password recovery does
not require modifying database records by hand.

## What changes

| Control | Who can use it | Result |
| --- | --- | --- |
| Change own password | Any active signed-in user | Replaces the password and invalidates all older access tokens. A new token is returned for the current session. |
| List organization users | Admin | Returns only users in the caller's organization, without password data. |
| Reset another user's password | Admin | Replaces a different user's password and invalidates their older tokens. |
| Enable or disable a user | Admin | Disabling immediately blocks the user's API access; enabling requires a new sign-in. |
| Prevent last-admin lockout | Platform | The last active Admin cannot be disabled and an Admin cannot disable their own account. |
| Tamper-evident audit trail | Platform | Password and account-status operations are added to the organization's audit chain. |

The dashboard now exposes password change for every user, plus user status and
password-reset controls for Admins.

## Token revocation

Every user has an internal credential epoch. Each signed JWT carries that epoch.
Changing a password, resetting a password, disabling, or enabling an account
increments the epoch. A token with an older epoch is rejected even if its normal
expiry time has not passed.

This gives AEGISAI immediate server-side token revocation without storing raw
tokens or passwords.

## API reference

All routes below require bearer authentication and return `Cache-Control:
no-store` because they are under `/auth/`.

### Change your password

```bash
curl --fail --request POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "current_password":"current-password",
    "new_password":"a-new-unique-password"
  }' \
  http://127.0.0.1:8000/auth/password/change
```

Store the returned `access_token` in place of the old token.

### Admin: list users

```bash
curl --fail \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:8000/auth/users | jq
```

### Admin: reset another user's password

```bash
curl --fail --request POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"new_password":"a-new-unique-password"}' \
  http://127.0.0.1:8000/auth/users/USER_ID/password-reset
```

### Admin: disable or re-enable a user

```bash
curl --fail --request PATCH \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"is_active":false}' \
  http://127.0.0.1:8000/auth/users/USER_ID/status
```

Use `{"is_active":true}` to re-enable the account. The user must sign in again.

## Login protection

Failed logins are rate-limited by client and email. A lockout returns HTTP 429
and a `Retry-After` header; wait for that window rather than retrying. Account
status controls do not bypass login throttling.

For production, put an additional shared edge rate limit and an organization
approved account-recovery process in front of the API. Email-based password
recovery is intentionally not implemented in this local release because it
requires verified mail delivery, signed short-lived recovery tokens, and a
separate abuse review.

## Upgrade

`make restart` runs Alembic automatically and applies
`0015_identity_ops`. Existing users receive credential epoch `0`. Tokens issued
before this upgrade do not contain that claim, so users must sign in once after
the restart.
