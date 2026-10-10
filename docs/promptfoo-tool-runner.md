# Promptfoo tool runner (local, authorized targets)

This integration runs the real Promptfoo CLI in a separate container and
imports its JSON evidence into AEGISAI. It is intentionally limited to an
approved, locally reachable Ollama target. It does not scan public systems,
discover targets, or send evaluation content to a remote red-team provider.

## Security boundary

- An Admin or Security Analyst must explicitly register the target and confirm
  authorization.
- The API validates the model endpoint against AEGISAI's existing local or
  explicitly approved endpoint allowlist.
- The Promptfoo container has no database credentials, no frontend secrets,
  no Linux capabilities, a read-only root filesystem, PID/memory/CPU limits,
  and temporary `/tmp` working storage only.
- Promptfoo's home, cache, and configuration directories are redirected to
  that temporary storage, so it cannot write to the container user's home or
  retain state between runs.
- A dedicated `AEGISAI_TOOL_RUNNER_TOKEN` authenticates the runner's claim and
  result-import calls. Use a unique 32+ character value outside local testing.
- Promptfoo version, immutable config digest, report digest, per-case outcome,
  and protected prompt/response evidence are persisted. A tool execution is
  not presented as ground-truth precision or complete model security coverage.

Container egress enforcement is environment-specific. For a production
deployment, apply a Kubernetes `NetworkPolicy`, ECS security group, or host
firewall so the runner can reach only the AEGISAI API and its approved model
endpoint.

## One-time local configuration

Add a long random value to the untracked `.env` file, then restart the stack:

```bash
openssl rand -hex 32
nano .env
# Set: AEGISAI_TOOL_RUNNER_TOKEN=<paste-the-generated-value>
make restart
```

Keep `AEGISAI_LOCAL_MODEL_ENDPOINTS` aligned with the endpoint you register.
For the Windows-host Ollama example used by this project:

```dotenv
AEGISAI_LOCAL_MODEL_ENDPOINTS=http://172.22.160.1:11434
# Required so the isolated container can call the internal API service.
AEGISAI_TRUSTED_HOSTS=localhost,127.0.0.1,api
```

## Run a real local evaluation

First, find your AI-system profile and locally installed model name:

```bash
curl http://127.0.0.1:8000/ai-systems/
ollama list
```

Set `SYSTEM_ID` and `MODEL_NAME` to values you own. The following creates an
approved local target. The `authorization_confirmed` field is deliberate: do
not register a model you do not have permission to test.

```bash
export SYSTEM_ID="replace-with-your-ai-system-id"
export MODEL_NAME="replace-with-your-ollama-model-name"

curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data "$(jq -n \
    --arg system_id "$SYSTEM_ID" \
    --arg model_name "$MODEL_NAME" \
    '{system_id:$system_id, name:"my-authorized-local-model", provider:"ollama", endpoint:"http://172.22.160.1:11434", model_name:$model_name, authorization_confirmed:true}')" \
  http://127.0.0.1:8000/tool-evaluations/targets
```

Copy the returned target `id`, create a pending run, and run the isolated
Promptfoo worker:

```bash
export TARGET_ID="replace-with-returned-target-id"
RUN_ID=$(curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data "{\"target_id\":\"$TARGET_ID\"}" \
  http://127.0.0.1:8000/tool-evaluations/runs | jq -r .id)

make promptfoo-run RUN_ID="$RUN_ID"
curl "http://127.0.0.1:8000/tool-evaluations/runs/$RUN_ID"
```

By default this creates the `aegisai_ai_security_baseline_v1` suite: twelve
controlled checks covering prompt injection, jailbreak resistance, encoded
instructions, secret and personal-data protection, RAG instruction poisoning,
agent export/network/destructive-action safety, and uncertainty handling. The
original three-case `aegisai_local_safety_smoke` suite remains available only
when explicitly requested for a quick connectivity check:

```bash
curl --fail --request POST \
  -H "Content-Type: application/json" \
  --data "{\"target_id\":\"$TARGET_ID\",\"suite_name\":\"aegisai_local_safety_smoke\"}" \
  http://127.0.0.1:8000/tool-evaluations/runs
```

Each baseline assertion is a deliberately limited heuristic. A passing
assertion is evidence that the model produced an expected safety signal; it is
not proof that the model is secure. A failed or unclear assertion must be
reviewed against the captured prompt and response before it becomes a finding.

`make promptfoo-run` rebuilds the isolated runner before execution. It exits
successfully once the report is imported, even when
Promptfoo finds a failed safety assertion. Check the saved run status and
per-case results; a detected finding is assessment evidence, not a runner
failure.

The initial `aegisai_local_safety_smoke` suite has three safe, deterministic
checks: normal safe support behavior, untrusted-document instruction handling,
and credential-sharing guidance. It is a verified Promptfoo execution, but it
is not a substitute for a full red-team assessment. Future adapters should add
Garak and PyRIT under the same target registration, runner isolation, evidence,
and authorization model.
