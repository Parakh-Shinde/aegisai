# Live AI Application Testing

AEGISAI can run its versioned Promptfoo safety baseline against an **authorized
OpenAI-compatible AI application**. This is for a staging or test deployment
you own, such as an internal RAG application or model gateway that implements
`POST /v1/chat/completions`.

It is deliberately not a generic URL scanner. Registering an arbitrary URL is
rejected. A target must be explicitly allowlisted and an analyst must confirm
authorization before a runner can call it.

## Security boundary

- The API stores endpoint metadata, approval status, test configuration
  digests, and encrypted request/response evidence.
- `AEGISAI_TARGET_API_KEY` remains only in the local environment and is passed
  only to the short-lived `promptfoo-runner` container.
- The API, database, dashboard, audit log, and imported report never return or
  store that credential.
- The runner has a read-only filesystem, temporary writable storage only,
  dropped Linux capabilities, `no-new-privileges`, resource limits, and a
  bounded timeout.
- The app endpoint must exactly match an application-target allowlist entry.
  Remote endpoints must resolve only to public IP addresses when registered.

An allowlist reduces SSRF risk but does not replace production network egress
controls or a dedicated staging environment. Test only systems you own or are
explicitly authorized to test.

## Configure a local staging application

Your application must expose an OpenAI-compatible base URL. For a Docker or
Windows-hosted app, edit `.env`:

```dotenv
AEGISAI_LOCAL_APPLICATION_ENDPOINTS=http://host.docker.internal:9000/v1
AEGISAI_TARGET_API_KEY=replace-with-the-staging-token
```

For a remote staging application, use HTTPS and an exact public allowlist:

```dotenv
AEGISAI_ALLOW_REMOTE_APPLICATION_TARGETS=true
AEGISAI_APPROVED_APPLICATION_ENDPOINTS=https://staging.example.com/v1
AEGISAI_TARGET_API_KEY=replace-with-the-staging-token
```

Then restart the stack:

```bash
make restart
```

## Register and run an authorized target

Replace the values below with your AI system ID, exact allowlisted endpoint,
and model/deployment name. The endpoint must include `/v1` when that is where
the application exposes its OpenAI-compatible API.

```bash
export SYSTEM_ID="your-ai-system-id"

TARGET_ID=$(curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data "$(jq -n \
    --arg system_id "$SYSTEM_ID" \
    '{system_id:$system_id,name:"authorized-staging-app",provider:"openai_compatible",endpoint:"http://host.docker.internal:9000/v1",model_name:"your-deployment-name",authorization_confirmed:true}')" \
  http://127.0.0.1:8000/tool-evaluations/targets | jq -r .id)

RUN_ID=$(curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data "{\"target_id\":\"$TARGET_ID\",\"suite_name\":\"aegisai_ai_security_baseline_v1\"}" \
  http://127.0.0.1:8000/tool-evaluations/runs | jq -r .id)

make live-app-run RUN_ID="$RUN_ID"
curl --fail "http://127.0.0.1:8000/tool-evaluations/runs/$RUN_ID" | jq
```

## Interpretation

The baseline records the exact prompt, output, assertion result, test version,
configuration digest, tool version, and run timestamps. A passing keyword
assertion is **not** proof that a model is secure. Failed, ambiguous, or
high-impact cases require analyst review, and a release decision must consider
coverage, evidence, and the target's real architecture.
