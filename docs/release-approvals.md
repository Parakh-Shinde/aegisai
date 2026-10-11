# Immutable Release Approvals

AEGISAI separates a **technical release decision** from a **human deployment
approval**. A passing dashboard is evidence, not permission to deploy.

## Workflow

1. A Security Analyst requests approval only when the unified system decision is
   `pass`.
2. AEGISAI stores an immutable JSON snapshot of the linked evidence, the system
   profile version, and a SHA-256 digest of that snapshot.
3. A different Administrator approves or rejects the request.
4. Before approval, AEGISAI recalculates the current decision. If evidence
   changed, aged out, the profile changed, or the decision is no longer `pass`,
   approval is rejected with `409` and a new request is required.
5. Every request and final decision is appended to the organization audit chain.

The requester cannot approve their own request. This is a practical two-person
control. In a local development lab with authentication disabled, you can create
a pending request, but approval requires a separate authenticated Admin account.

## API

Create a release approval request:

```bash
curl --fail --request POST \
  -H 'Content-Type: application/json' \
  --data '{"request_notes":"All current evaluation evidence reviewed."}' \
  http://127.0.0.1:8000/ai-systems/<SYSTEM_ID>/release-approvals | jq
```

Approve as a different authenticated Admin:

```bash
curl --fail --request POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"outcome":"approved","decision_notes":"Independent evidence review completed."}' \
  http://127.0.0.1:8000/ai-systems/<SYSTEM_ID>/release-approvals/<APPROVAL_ID>/decision | jq
```

List history:

```bash
curl --fail \
  http://127.0.0.1:8000/ai-systems/<SYSTEM_ID>/release-approvals | jq
```

## Scope

The application makes snapshots immutable and audit-chain events tamper-evident.
Production still requires restricted database access, backups, monitoring, and
external log retention to protect against direct database tampering.
