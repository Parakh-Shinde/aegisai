# Adaptive AI Security Coverage

AEGISAI v0.9 begins with the question that must be answered before a campaign:
**what can this AI system receive, access, and do?** A text-only assistant, a
public RAG application, and a browser-enabled agent do not have the same attack
surface and must not receive the same security claim.

## AI system profile

Create a profile in the dashboard before testing. The profile captures:

- system type: assistant, RAG application, agent, multimodal system, or model API;
- accepted input modalities: text, image, document, audio, and video;
- enabled capabilities: RAG, tools, browser, code execution, external APIs,
  customer data, and multi-tenancy;
- deployment exposure: internal, partner, or public; and
- data classification: public, internal, confidential, or regulated.

Profiles are organization-scoped and auditable. A RAG profile automatically
declares RAG capability; an agent profile automatically declares tool use; a
multimodal profile must declare at least one non-text input.

Use `PATCH /ai-systems/PROFILE_ID` with a complete revised profile when the AI
system gains a new modality, tool, data source, or exposure level. A profile
update increments its version and records an audit event.

## Coverage plan

AEGISAI converts the profile into a coverage plan. Each pack is one of:

- **available** — currently implemented and runnable in AEGISAI; or
- **partial** — AEGISAI implements a limited safety control but does not claim
  full attack-surface coverage; or
- **planned** — a real attack surface that AEGISAI has identified but does not
  yet claim to test automatically.

The coverage percentage is therefore an **automated test-pack coverage
indicator**, not a guarantee that the system is secure. Partial and planned
packs are intentional, visible gaps that should block an overconfident release
claim.

Currently available packs cover text model behavior and governance:

- prompt-injection resistance;
- jailbreak resistance;
- sensitive-data exposure; and
- analyst evidence review and release gating.

Multimodal input security and document/file safety are currently **partial**:
the File Security Gateway performs non-executing structural checks but does not
claim OCR-based hidden-text detection, malware-engine scanning, content disarm,
or dynamic analysis. Other planned packs include RAG poisoning, agent tool
safety, browser indirect prompt injection, public API abuse resistance, and
privacy assurance.

## API

Create a profile:

```bash
curl --fail --request POST \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "support-agent-staging",
    "description": "Customer support RAG agent with approved internal tools.",
    "system_type": "agent",
    "deployment_exposure": "internal",
    "data_classification": "confidential",
    "input_modalities": ["text", "document"],
    "capabilities": ["rag", "agent_tools", "customer_data"]
  }' \
  http://127.0.0.1:8000/ai-systems/
```

Retrieve the plan using the returned profile ID:

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  http://127.0.0.1:8000/ai-systems/PROFILE_ID/coverage
```

Do not create a profile that describes production data or live tools as a test
target. Use a staging system with test data and harmless tool substitutes.
