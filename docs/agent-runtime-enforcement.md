# Agent Runtime Enforcement

AEGISAI v0.13 adds the integration endpoint that an agent runtime calls **before
it executes a tool action or navigation**. The endpoint returns a decision; the
agent must enforce that decision locally.

## Decision contract

| Decision | `execution_permitted` in enforce mode | Agent behavior |
|---|---:|---|
| `allow` | `true` | The action passed current static policy checks. The runtime may continue under its own safeguards. |
| `require_review` | `false` | Pause the action and request an authorized human decision. |
| `deny` | `false` | Do not execute the action. |

The endpoint does not execute tools, make network requests, resolve DNS, or
access connectors. It records an immutable decision and returns the decision to
the caller. If an external agent ignores that response, AEGISAI cannot stop it.

## Authentication and rollout

Set these production values in `.env`:

```dotenv
AEGISAI_AGENT_GATEWAY_TOKEN=replace-with-a-unique-32-character-or-longer-secret
AEGISAI_AGENT_ENFORCEMENT_MODE=enforce
```

Production refuses to start without this token and enforce mode. A local
development lab may leave the token blank so you can test the endpoint. Never
expose a development instance to an untrusted network.

`observe` mode returns the risk decision but sets `execution_permitted` to true.
It exists only for a tightly controlled staging rollout; do not use it for a
production agent.

## Runtime call

An agent should generate a new idempotency key per proposed action, call the
gateway, and execute only when `execution_permitted` is `true`.

```bash
curl --fail --request POST \
  -H "Content-Type: application/json" \
  -H "X-AEGISAI-Agent-Token: ${AEGISAI_AGENT_GATEWAY_TOKEN}" \
  -H "Idempotency-Key: action-20261010-001" \
  --data '{
    "system_id": "PROFILE_ID",
    "action_type": "browser_navigation",
    "tool_name": "knowledge_browser",
    "target": "https://docs.example.com/help",
    "arguments": {"query": "approved support policy"},
    "page_excerpt": "Approved staging support documentation."
  }' \
  http://127.0.0.1:8000/agent-security/enforce
```

Retry the same request with the same `Idempotency-Key` to receive the same
recorded decision without creating a second action record.

Do not send production credentials, customer data, real malware, or destructive
commands to a development lab.
