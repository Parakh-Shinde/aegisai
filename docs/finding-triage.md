# Finding Triage Workflow

AEGISAI v0.7 adds a lightweight security-case workflow to the existing evidence
review flow. A test result remains immutable evidence; triage records the
operational decision made about that evidence.

## Triage states

| State | Meaning | Required action |
|---|---|---|
| `open` | A medium or high severity result needs ownership. | Claim or assign it. |
| `in_progress` | An analyst is investigating or mitigating it. | Keep evidence and notes current. |
| `resolved` | The issue was fixed or safely closed. | Provide a resolution note. |
| `accepted_risk` | An accountable decision accepts the remaining risk. | Provide the decision rationale. |

Only Security Analysts and Administrators can change triage. Every change is
organization-scoped and recorded in the tamper-evident audit chain. Viewers can
read evidence but cannot claim, change, or resolve findings.

## SLA deadlines

New results receive a default deadline when created:

| Severity | Default deadline |
|---|---|
| High | 24 hours |
| Medium | 72 hours |
| None | 7 days |

The dashboard shows active, unassigned, overdue, and high-severity findings.
Historical results have no retroactive deadline, so they will not be counted as
overdue merely because this feature was added later.

## Analyst workflow

1. Run or load a campaign.
2. Filter the History table by severity and triage state.
3. Open evidence details, then use **Claim** to assign the finding to yourself.
4. Confirm the result through the existing review controls.
5. When remediation is complete, choose **Resolve** and enter a concise note.
6. Re-run the affected campaign and confirm the release gate before accepting a
   release decision.

Triage does not override the release gate. An unresolved leaked, high-severity,
or unreviewed result still blocks a passing release decision.

## API examples

List open high-severity findings for the authenticated organization:

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  "http://127.0.0.1:8000/security-tests/findings?triage_status=open&severity=high"
```

Claim and start work on a finding:

```bash
curl --fail --request PATCH \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"triage_status":"in_progress","assign_to_me":true}' \
  http://127.0.0.1:8000/security-tests/results/TEST_ID/triage
```

Use a real `TEST_ID` from your dashboard; do not paste secrets in triage notes.
