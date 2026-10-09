# Release Automation

AEGISAI v0.5 adds a free, deterministic CI release gate. It protects the
evaluation assets that make regression comparisons meaningful; it does not
pretend that GitHub-hosted CI can test a model running only on a developer's
computer.

## What `release-gate` enforces

- Every committed corpus JSON file is listed in
  [`backend/release/evaluation-policy.json`](../backend/release/evaluation-policy.json).
- Each listed corpus has the approved suite name, semantic version,
  scoring-rule version, SHA-256 digest, and minimum test count.
- A new or changed corpus fails CI until the policy is deliberately reviewed
  and updated.
- The job writes `release-integrity.json`, uploads it as a GitHub Actions
  artifact, and—on a public repository's `main` push—creates a GitHub artifact
  attestation for it.

The attestation uses GitHub Actions provenance. It is not a replacement for a
human release decision or a production deployment signature.

## Local validation

After rebuilding the Docker image, run:

```bash
make release-gate
```

This writes a report inside the temporary container and exits non-zero when
the policy is violated. The CI artifact is the durable report for a merged
revision.

## Pull-request protection

On GitHub, configure this once:

1. Open the repository **Settings → Branches**.
2. Add a protection rule for `main`.
3. Enable **Require a pull request before merging**.
4. Enable **Require status checks to pass before merging** and select
   `release-gate` (plus `backend`, `frontend`, `security`, and
   `infrastructure`).
5. Enable **Require review from Code Owners**.

`CODEOWNERS` marks corpus, release-policy, and CI workflow changes for the
repository owner. Branch protection is what turns the check into a mandatory
merge barrier.

## Verifying a main-branch report

Download `aegisai-release-integrity` from the successful Actions run, then use
GitHub CLI:

```bash
gh attestation verify release-integrity.json -R Parakh-Shinde/aegisai
```

GitHub artifact attestations are available on public repositories on GitHub
Free. If the repository is private on a non-Enterprise plan, the workflow
still validates and uploads the report, but the attestation step is skipped.

## Real model release workflow

For each candidate model or prompt change:

1. Run a versioned campaign in AEGISAI.
2. Review every finding.
3. Require a passing release gate.
4. Compare it with an approved baseline using the identical corpus digest.
5. Export the reproducible campaign report and attach it to the change review.

The CI gate protects the corpus/scoring contract; the reviewed campaign gate
protects the candidate model decision. Both must pass.
