# Security Reporting

AEGISAI v0.8 turns tenant-scoped campaign, review, and triage records into a
small operational security report. It is designed for a security lead who needs
to understand the current model-safety posture without exposing raw test
evidence in a spreadsheet.

## Dashboard reporting window

The dashboard loads a rolling 30-day report with:

- tests, campaigns, and models evaluated;
- review-completion percentage;
- active and overdue medium/high-severity findings;
- release-gate outcomes for campaigns touched in the window; and
- review and triage action counts per internal reviewer identifier.

Use **Print / PDF** on the reporting card to save this summary as a PDF from
the browser print dialog. The print layout contains only the posture report,
not raw campaign evidence.

Release counts are derived from each complete campaign, rather than from a
partial time-window slice. This prevents a campaign from appearing to pass just
because its earlier risky result was outside the dashboard window.

## APIs

All endpoints are organization-scoped. A user can only retrieve data belonging
to their own organization.

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  "http://127.0.0.1:8000/security-tests/reports/overview?days=30"
```

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  "http://127.0.0.1:8000/security-tests/reports/reviewer-activity?days=30"
```

Export medium- and high-severity findings only:

```bash
curl --fail --output aegisai-findings.csv \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  "http://127.0.0.1:8000/security-tests/reports/findings.csv?triage_status=all"
```

Use `open`, `in_progress`, `resolved`, or `accepted_risk` to filter the CSV by
triage state.

## Export safeguards

The findings CSV intentionally includes metadata, finding summaries, and
recommendations only. It never includes the protected raw prompt or raw model
response fields. Each cell that could be interpreted as a spreadsheet formula
is prefixed safely before export. Every CSV export is recorded in AEGISAI's
tamper-evident audit chain.

For evidence review, use the authenticated campaign report in the dashboard;
do not distribute raw evidence through a spreadsheet.
