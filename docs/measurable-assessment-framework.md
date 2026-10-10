# Measurable Assessment Framework

AEGISAI v0.16 adds measurable evidence to the controlled agent-runtime policy
benchmark. A successful API call is not interpreted as proof that a system is
secure.

## What is measured now

Each run of `agent_runtime_adversarial_suite` persists a report containing:

- planned, executed, skipped, and unsupported test counts;
- test-execution rate and applicable test coverage, each with its denominator;
- true positives, false positives, false negatives, and true negatives;
- precision, recall, and false-positive rate against committed ground truth;
- static-policy evaluation duration and mean time to detect a known risky case;
- corpus name, version, SHA-256 digest, scoring-rule version, and evidence IDs.

For this suite, a case is ground-truth risky when the expected verdict is
`blocked` or `quarantined`. A detection is an actual `blocked` or `quarantined`
verdict. The metrics therefore measure AEGISAI's static policy engine against
the committed controlled benchmark—not an external scanner or a production
agent.

## What is deliberately unavailable

The report explicitly returns `status: "unavailable"` for these metrics until
the required evidence exists:

- external tool reliability;
- CPU, memory, storage, and execution cost;
- remediation success rate;
- regression rate after a previously fixed finding is retested.

Missing evidence is never shown as a zero vulnerability count or as a passing
metric.

## Run and reproduce an assessment

Run the controlled benchmark:

```bash
curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data '{"system_id":"PROFILE_ID"}' \
  http://127.0.0.1:8000/agent-security/evaluations/run
```

Save the returned `run_id`, then retrieve the same persisted report later:

```bash
curl http://127.0.0.1:8000/agent-security/evaluations/RUN_ID
```

The report is tenant-scoped, retains a snapshot of its metrics, and links every
case to an action-evidence record. A later corpus change cannot silently alter
the metrics already stored for that run.

## Next practical expansions

To satisfy the complete framework, the next controlled milestones are:

1. Deliberately vulnerable and hardened reference targets for model, RAG, and
   agent flows.
2. Finding-to-remediation links and comparable retest procedures.
3. Sandboxed tool-proxy execution telemetry for reliability and resources.
4. A coverage matrix that distinguishes tested, failed, skipped, unsupported,
   and inconclusive checks across every supported security area.
5. Isolated adapters for industry AI-security tooling such as Garak, Promptfoo,
   and Microsoft PyRIT, with versions and output digests recorded as evidence.

Until those controls exist, AEGISAI documents the gaps instead of claiming
full enterprise effectiveness measurement.
