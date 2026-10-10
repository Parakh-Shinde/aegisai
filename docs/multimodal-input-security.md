# Multimodal Input Security

AEGISAI's file-security gateway performs bounded, static checks before an
uploaded document or image is sent to a model, OCR service, RAG index, or agent
runtime. The gateway does not execute, render, extract to disk, or forward the
original upload.

## Checks performed

| Input | Static checks | Result on risk |
|---|---|---|
| Images | Signature/extension match, PNG text metadata, EXIF/XMP indicators, bounded dimensions | Quarantine metadata instruction markers or oversized images |
| PDFs | Signature match and active-content markers (`JavaScript`, launch, auto-open, embedded files) | Quarantine |
| Office documents | Safe in-memory ZIP inspection, traversal/encryption/macro checks, bounded Word/Excel/PowerPoint XML text inspection | Quarantine macros or instruction markers |
| Text/CSV/JSON | UTF-8 safety and prompt-injection marker checks | Quarantine flagged content |

The API records a SHA-256 digest, metadata, decision, signals, and audit event.
It does **not** persist the uploaded content.

## Test a safe file

```bash
printf 'AEGISAI safe upload test\n' > /tmp/aegisai-safe-test.txt
curl -F "file=@/tmp/aegisai-safe-test.txt;type=text/plain" \
  http://127.0.0.1:8000/file-security/scans | jq
```

## What a quarantine means

`quarantined` means the file must stay out of the model/RAG path until a
security analyst reviews it. It is not proof that the file is malicious.

`blocked` means its type or structure cannot be verified safely and should be
rejected.

## Limits and next control

This release detects text present in supported document structures and image
metadata. It does not perform OCR or claim to detect instructions encoded only
in image pixels. OCR should be a separate, sandboxed, resource-limited stage;
its extracted text must be sent back through the same RAG-source inspection and
human-review workflow before indexing.
