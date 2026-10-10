# Agent Action Security Gateway

AEGISAI v0.12 inspects a **proposed** agent action before an operator permits it
in a real agent runtime. It evaluates the metadata that you provide and records
only a digest, verdict, signals, and audit trail.

## What it does

- requires a tenant-scoped AI system with agent, browser, external-API, or code
  capability enabled;
- blocks shell-command actions, local/private IP targets, URLs with credentials,
  invalid network targets, absolute paths, and path traversal;
- quarantines data exports, destructive-operation markers, secret-like argument
  field names, and common indirect prompt-injection signals in a pasted browser
  page excerpt;
- requires an administrator to record an exception for a quarantined action;
- never executes a command, opens a URL, resolves DNS, accesses a connector, or
  stores action arguments or browser-excerpt text.

## Important limit

This is a static policy decision layer, not a live agent runtime. An `allowed`
result does not execute the action and is not proof that it is safe. Your actual
agent must enforce its own tool allowlist, least-privilege credentials, isolated
runtime, outbound network policy, confirmation gates, and monitoring.

## API

Create an agent-capable AI System profile first. Then inspect only a harmless
staging action:

```bash
curl --fail --request POST \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "system_id": "PROFILE_ID",
    "action_type": "browser_navigation",
    "tool_name": "knowledge_browser",
    "target": "https://docs.example.com/help",
    "arguments": {"query": "approved support policy"},
    "page_excerpt": "Approved staging support documentation."
  }' \
  http://127.0.0.1:8000/agent-security/actions/inspect
```

View recent decisions:

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  http://127.0.0.1:8000/agent-security/actions
```

Do not submit production credentials, customer data, destructive commands, or
targets you do not own to a development lab.
