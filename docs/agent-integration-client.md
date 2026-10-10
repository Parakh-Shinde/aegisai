# Agent Integration Client

AEGISAI v0.15 includes a small Python client that turns the enforcement API into
a fail-closed pre-action check for a real agent runtime.

The client does not execute tools itself. Your agent gives it the operation to
run; the operation is called only when AEGISAI returns both `allow` and
`execution_permitted: true`. Network failures, malformed responses, `deny`, and
`require_review` all prevent the operation from running.

## Local verification

With the Docker lab running, test the client against an existing agent profile:

```bash
make agent-gateway-demo SYSTEM_ID=PROFILE_ID
```

The local demo calls the API from inside the API container. It uses a harmless
documentation URL and prints a gateway decision. It does not open the URL.

## Integrate a real Python agent

Copy or package `backend/app/integrations/agent_gateway.py` with the agent
runtime. Store the token only in the runtime's secret store or environment—not
in browser code, source control, tool prompts, or action arguments.

```python
from app.integrations.agent_gateway import AgentActionProposal, AgentGatewayClient

with AgentGatewayClient(
    gateway_base_url="https://aegisai.company.example",
    system_id="YOUR_AGENT_PROFILE_ID",
    token="READ_FROM_SECRET_MANAGER",
) as gateway:
    result = gateway.execute(
        AgentActionProposal(
            action_type="browser_navigation",
            tool_name="knowledge_browser",
            target="https://docs.example.com/help",
            arguments={"query": "approved support policy"},
            page_excerpt="Untrusted page text goes here.",
        ),
        operation=lambda: your_agent_browser.navigate("https://docs.example.com/help"),
    )
```

The action actually executed by `operation` must match the action that was just
authorized. Do not modify the URL, tool name, arguments, or page excerpt after
the decision; instead submit a new proposal and obtain a new decision.

## Deployment rules

- Use HTTPS in every shared, staging, and production environment.
- The client refuses plain HTTP unless `allow_insecure_http=True` is explicitly
  set for a local-only lab.
- Set a short timeout; the client defaults to five seconds and limits it to
  1–30 seconds.
- Use one idempotency key per proposed action. The client creates one when the
  caller does not supply it.
- Treat gateway errors as a stop condition. Do not add a fail-open fallback.

The helper is not a sandbox and cannot stop an agent that bypasses it. Place it
immediately before every browser, HTTP, file, connector, and tool call, and
restrict direct access to the underlying tools.
