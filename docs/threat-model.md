# AEGISAI Threat Model

## Assets to protect

- Customer prompts, model responses, findings, and review notes.
- Organization boundaries and release decisions.
- User identities, roles, sessions, and provider credentials.
- Campaign workers, queue state, and model endpoints.

## Trust boundaries

1. Browser to API: untrusted user input crosses into authenticated services.
2. API to PostgreSQL/Redis: tenant-scoped application data crosses into private
   persistence services.
3. Worker to model endpoint: adversarial test content crosses into a controlled
   model provider.
4. CI to artifact registry/deployment: source becomes a released container.

## High-priority threats and controls

| Threat | Impact | Required control |
|---|---|---|
| Broken tenant authorization | One customer reads another customer’s evidence | Organization-scoped queries, RBAC checks, negative authorization tests, pen test |
| SSRF through model registration | Scanning cloud metadata or internal services | Exact endpoint allowlist, public-resolution checks, private egress policy |
| Prompt/evidence disclosure | Customer content reaches unauthorized users | Encryption, least privilege, retention policy, reviewable audit trail |
| Worker escape or resource exhaustion | Host compromise or denial of service | Per-job isolation, non-root execution, CPU/memory/time quotas, no Docker socket |
| Credential compromise | Full tenant/admin access | SSO/MFA, short sessions, secret manager, rotation, anomaly alerts |
| Supply-chain compromise | Malicious code/image enters production | Protected branches, SBOM, signed images, dependency and image scans |
| Audit-log tampering | Loss of accountability | Hash-chain verification, restricted writers, immutable off-platform export |

## Security assumptions

- Customer-provided prompts and model outputs are untrusted.
- A passing safety score does not prove a model is safe.
- Public deployment is blocked until the release gates in
  `enterprise-blueprint.md` are met.
