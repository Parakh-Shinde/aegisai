# RAG Source Security Ledger

AEGISAI v0.11 adds a source-inspection workflow for staged RAG content. Before
an operator manually indexes a source in a knowledge base, AEGISAI can inspect
the submitted text, record a content digest and verdict, and create an audit
trail for the decision.

## What it does

- requires the source to belong to a tenant-scoped AI system with RAG enabled;
- detects common indirect prompt-injection, role impersonation, secret-extraction,
  tool-action, hidden HTML comment, and invisible Unicode control markers;
- records only metadata, SHA-256 digest, character count, verdict, and signals;
- never fetches URLs, accesses connectors, indexes the source, or sends its text
  to a model; and
- quarantines suspicious sources for review. Only an administrator can record an
  exception that makes a quarantined source eligible for manual indexing.

The original source text is deliberately not stored by AEGISAI. Keep it in your
approved source repository and use the digest to link the security decision to
the exact reviewed revision.

## Important limit

An **approved** source passed only the currently configured static checks. It is
not proof that the source is safe, trustworthy, or free from hidden attacks.
Your real RAG application must still enforce source allowlists, retrieval-time
instruction isolation, least-privilege connectors, citations, and monitoring.

## API

Create a RAG-enabled AI System profile first. Then submit only a harmless
staging sample:

```bash
curl --fail --request POST \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "system_id": "PROFILE_ID",
    "source_name": "staging-support-policy",
    "source_kind": "staging_text",
    "source_reference": "kb://staging/support-policy/v1",
    "content": "Support agents may summarize approved policy documents."
  }' \
  http://127.0.0.1:8000/rag-security/sources/inspect
```

List decisions:

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  http://127.0.0.1:8000/rag-security/sources
```

Do not submit customer records, production secrets, real malware, or live
connector credentials to a development lab.
