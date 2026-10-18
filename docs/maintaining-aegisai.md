# Maintaining AegisAI

This guide describes how to make changes that are reviewable, testable, and safe to maintain. It complements the feature-specific guides in this directory; it does not claim that every feature is production-ready.

## Working principle

Make the smallest change that fixes a demonstrated problem. Explain the behaviour that should change, add a regression test where practical, and verify the result before expanding the scope. A large diff is not evidence of better engineering.

AegisAI is a security workbench for AI-model and AI-application evaluations. A change should make it easier to answer three questions:

1. What behaviour did the system observe?
2. What evidence supports the result?
3. What decision can a reviewer safely make from that evidence?

Avoid claims that go beyond the code, configured test suite, and recorded evidence.

## Repository map

| Path | Responsibility |
| --- | --- |
| `backend/app/api/` | FastAPI route handlers and HTTP-level validation |
| `backend/app/core/` | Runtime configuration, authentication, shared security controls, database and execution utilities |
| `backend/app/models/` and `backend/app/db/` | Request/domain models and persistence models |
| `backend/app/services/` | Evaluation logic, adapters, reporting, policy and security analysis |
| `backend/app/corpus/` | Versioned evaluation cases used by the project |
| `backend/tests/` | Backend behavioural and security regression tests |
| `backend/migrations/` | Alembic schema history; migrations should be reviewed as data changes |
| `frontend/src/App.tsx` | Current React application entry component and substantial UI state/workflow logic |
| `frontend/src/App.css` | Main dashboard styling |
| `docs/` | Feature-specific setup, security and operational notes |
| `.github/workflows/` | Automated CI and release checks |

This map is a navigation aid, not a strict architectural rule. Before moving code, inspect imports, API contracts, tests, and deployment packaging.

## Local development workflow

Start with a clean understanding of the current checkout. These commands are read-only:

```bash
git status --short --branch
git log -1 --oneline
git diff --stat
```

If the working tree contains changes, identify which ones belong to the current task before editing. Never use `git reset --hard`, `git clean -fd`, or a broad checkout command to make the tree look clean.

The project Makefile provides the primary local workflows:

```bash
make doctor
make config-check
make test
make lint
```

- `make doctor` validates the Docker Compose configuration.
- `make config-check` builds/runs the runtime configuration verifier without starting dependent services.
- `make test` runs the backend test target.
- `make lint` runs the configured backend lint/type checks and frontend lint workflow.

Run commands in the project environment and read their exit status and output. If a command cannot run because Docker, dependencies, or a service is unavailable, report it as **not run**—not as a pass. Check the current Makefile before relying on this list because targets can evolve.

For frontend-only changes, also run the frontend build from the frontend package environment:

```bash
cd frontend
npm run build
npm run lint
```

Return to the repository root before running root-level Makefile commands.

## How to make a change

### 1. State the behaviour

Write down the current behaviour, expected behaviour, and risk if the current behaviour remains. Prefer a reproducible example over descriptions such as “clean up this code.”

### 2. Find the owner of the behaviour

Keep HTTP concerns in route handlers, reusable policy in the appropriate service/core module, and presentation logic in the frontend. Do not introduce another abstraction merely to wrap one function call.

### 3. Add a focused regression test

A useful test should fail if the defect returns. Prefer testing externally observable behaviour or a security invariant over the exact sequence of internal function calls. Keep fixtures isolated and avoid depending on live model providers or network access unless the test is explicitly an integration test.

For security configuration, test both a valid configuration and the invalid values that must be rejected. Use fake test credentials and non-routable example hostnames; never put live secrets in tests.

### 4. Implement the smallest coherent fix

Preserve API response shapes unless a deliberate contract change is part of the task. Avoid unrelated formatting churn, broad exception handling, blanket lint suppressions, and silent fallback behaviour that makes security failures hard to see.

### 5. Verify and inspect the diff

Run the smallest relevant test first, then broader checks. Review the final diff for:

- Accidental feature removal or changed API contracts.
- Secrets, personal data, or sensitive prompts in logs and fixtures.
- Weakened authentication, authorization, validation, or tests.
- Incorrect documentation or unsupported claims.
- Unnecessary files, duplicated code, and generated artifacts.
- Migration compatibility and rollback implications, where applicable.

## Frontend maintainability

The main frontend component still contains a large amount of domain typing, UI state, and workflow rendering. Shared JSON API transport has been moved into `frontend/src/lib/api.ts`; feature-specific upload/download requests remain in the component. Continue incrementally rather than rewriting the dashboard all at once.

A sensible order is:

1. Identify cohesive sections and their state dependencies.
2. Extract pure formatting and mapping helpers that can be tested without React.
3. Keep shared JSON requests in the typed client; consider extracting upload/download requests only when doing so preserves their distinct headers, response types, and error handling.
4. Extract components where they own a clear UI responsibility and stable inputs.
5. Extract hooks only where stateful behaviour is genuinely reusable or has a clear lifecycle.
6. Run TypeScript build and lint after each extraction and compare the UI behaviour.

Avoid creating a file for every type or tiny JSX fragment. A component should have a clear responsibility, and state should remain close to the workflow that owns it. Preserve keyboard access, labels, loading/error states, authentication behaviour, and responsive layouts.

## Backend and security review

For each change touching a protected operation, verify:

- Authentication is required where expected.
- Authorization is checked for the specific resource and operation, not just at the UI.
- Tenant/organization boundaries are enforced server-side.
- Inputs are bounded and validated.
- Errors do not expose credentials, stack traces, internal endpoints, or sensitive payloads.
- Logs contain enough context to investigate without unnecessarily storing secrets or raw user data.
- External model calls have bounded timeouts and explicit failure handling.
- Production configuration fails closed when required safeguards are missing.
- Tests exercise both accepted and rejected paths.

Do not assume that hiding a button is an authorization control. Do not assume that a successful model response means the requested action is safe.

## AI evaluation quality

Treat a test result as evidence for the tested case, suite version, model/provider, configuration, and scoring rule—not as a general proof of safety.

When adding or changing evaluation logic:

- Keep test-case identity and suite provenance stable and traceable.
- Distinguish an evaluation infrastructure error from a security failure.
- Preserve uncertainty rather than converting it into a pass.
- Document how expected outcomes are assigned and how metrics are calculated.
- Report denominators and unavailable metrics where meaningful.
- Include regression cases for parser edge cases and malformed provider output.
- Never invent benchmark results or relabel synthetic fixtures as real-world incidents.

## Documentation style

Write for the next developer who must run, debug, or change the feature.

Good documentation names the actual command, file, configuration key, expected outcome, and failure mode. Explain why a non-obvious security decision exists. Keep limitations explicit. Remove claims that are no longer true when the implementation changes.

Do not add comments that merely restate a line of code. Do not invent a project history or rationale. If a design decision is unknown, describe the observable behaviour and mark the rationale as unresolved.

## Pull-request checklist

Before requesting review, confirm as applicable:

- [ ] The change addresses a specific problem or documented maintenance goal.
- [ ] Existing local work was preserved.
- [ ] A regression test covers the changed behaviour.
- [ ] Backend tests and lint/type checks were run where applicable.
- [ ] Frontend build and lint were run where applicable.
- [ ] Docker/configuration and release checks were run where applicable.
- [ ] The diff contains no secrets or unrelated churn.
- [ ] API contracts and database migrations were reviewed.
- [ ] Documentation reflects verified behaviour.
- [ ] The PR describes checks that actually ran and lists anything not verified.

A check that was not run must be labelled as not run. Passing CI does not replace reviewing security-sensitive changes.
