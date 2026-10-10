# Agent Runtime Evaluation

AEGISAI v0.14 supplies a committed, versioned set of adversarial checks for the
agent-action policy. It is designed to catch a regression before the policy is
used to approve real agent actions.

## What the suite does

The suite uses static test data only. It never executes a tool, opens a URL,
resolves DNS, reads a file, calls a connector, or sends a shell command.

| Coverage | Expected behavior |
|---|---|
| Internal or localhost HTTP targets | Blocked |
| `file://` browser navigation | Blocked |
| Indirect browser prompt injection | Quarantined for review |
| Shell command proposals | Blocked |
| Data export or secret-bearing connector arguments | Quarantined for review |
| File path escapes | Blocked |
| Normal approved web navigation | Allowed |

Each run records the corpus version, SHA-256 digest, scoring-rule version, case
identifier, decision, and signals. It does not store the test arguments or
page content as evidence.

## Run the suite

Only a Security Analyst or Admin can run it. Use an agent-capable AI-system
profile ID:

```bash
curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data '{"system_id":"PROFILE_ID"}' \
  http://127.0.0.1:8000/agent-security/evaluations/run
```

A healthy run returns `"evaluation_status":"passed"` and eight passing
cases. A failed run means the live action-policy behavior no longer matches the
committed expected decisions. Treat that as a release blocker until reviewed.

## Release integrity

`backend/release/evaluation-policy.json` locks this corpus by name, version,
scoring-rule version, hash, and minimum test count. Therefore CI's
`make release-gate` fails if the committed evaluation asset changes without an
intentional policy update and review.

This suite evaluates AEGISAI's policy engine. To evaluate a real external
agent, that agent must call `/agent-security/enforce` before execution and honor
the returned `execution_permitted` field.
