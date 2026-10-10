# Unified System Release Decision

`GET /ai-systems/{system_id}/release-decision` produces a read-only, tenant-
isolated decision for one AI system profile. It never runs a test or changes
stored evidence.

The decision aggregates only records linked to that system:

- approved model targets and model security campaigns;
- the most recent completed external tool evaluation, such as Promptfoo;
- file-security scans when the profile accepts file-based input;
- RAG source inspections when RAG is enabled; and
- the latest agent runtime evaluation when agent tools are enabled.

Each evidence source is `pass`, `manual_review_required`, `fail`, or
`not_applicable`. Missing applicable evidence is always
`manual_review_required`; it is never treated as a pass. The overall decision
is the highest-severity applicable evidence status.

Passing evidence is also checked for freshness. The default maximum age is 168
hours (7 days), configured with `AEGISAI_RELEASE_EVIDENCE_MAX_AGE_HOURS`.
Evidence becomes stale, and the overall decision requires manual review, when
it is older than that limit or when the AI system profile changed after the
evidence was created. A newly approved model target also requires its own
completed external-tool evaluation.

Example:

```bash
curl --fail \
  http://127.0.0.1:8000/ai-systems/<SYSTEM_ID>/release-decision | jq
```

The response includes only identifiers and summaries, not raw model prompts,
model responses, OCR text, credentials, or other protected evidence. The
dashboard shows the same decision under **AI Systems**.

## Interpretation

`pass` means the linked evidence currently meets the implemented release
criteria. It does not certify an AI system as universally secure. The decision
must be regenerated after a model, prompt, tool, RAG corpus, input path, or
deployment change. Coverage limitations remain visible in every response.
