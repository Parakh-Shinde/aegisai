# Evaluation Integrity

AEGISAI v0.4 makes model-security results reproducible and comparable. A
dashboard score alone is not release evidence: the test corpus and scoring rule
must be known and stable.

## What is recorded

Every corpus campaign now stores, with each result:

- Corpus suite name and semantic version.
- SHA-256 digest of the exact corpus file used.
- Scoring-rule version.
- Immutable evidence fingerprint for the campaign report.

The fingerprint is calculated from the persisted test evidence and verdicts. If
the stored evidence changes, the report fingerprint changes too.

## Baseline workflow

1. Run a versioned corpus campaign.
2. Review every finding.
3. Confirm that the release gate returns `pass`.
4. Save it as an approved baseline.
5. Run the same corpus against a candidate model/version.
6. Compare the candidate campaign with the saved baseline.

Only a fully reviewed passing campaign can become a baseline. A candidate using
a different corpus digest or scoring-rule version is **not comparable** and is
sent to manual review.

## API workflow

Replace `MODEL` and `CAMPAIGN_ID` with values from your local dashboard/API.

```bash
# Run a versioned suite (local development mode)
curl -X POST http://127.0.0.1:8000/security-tests/suite/basic \
  -H 'Content-Type: application/json' \
  -d '{"model":"MODEL","suite_name":"basic_safety_suite"}'

# Produce a reproducible report
curl http://127.0.0.1:8000/security-tests/campaigns/CAMPAIGN_ID/report

# Create an approved baseline only after every finding is reviewed and the gate passes
curl -X POST \
  http://127.0.0.1:8000/security-tests/campaigns/CAMPAIGN_ID/baselines/approved-v1

# Compare a later campaign with the baseline
curl 'http://127.0.0.1:8000/security-tests/campaigns/CAMPAIGN_ID/regression?baseline_name=approved-v1'
```

When authentication is enabled, send the bearer token with each request.

## Honest limitation

The current risk scorer is marker/rule based. It gives repeatability and makes
regressions visible; it does not prove that a model is safe. Human review and
broader adversarial testing remain required before release.
