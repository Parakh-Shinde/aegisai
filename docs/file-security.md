# File and Document Security Gateway

AEGISAI v0.10 adds a non-executing inspection step for files before they are
accepted as AI model input. This is designed for staged AI systems that accept
images, documents, Office files, archives, or text uploads.

## What the scanner does

For each upload, AEGISAI reads the file in memory up to the configured limit and
records only inspection metadata: filename, declared type, detected type,
SHA-256 digest, size, signals, verdict, and recommendation. It does **not**
persist the original file, execute it, render it, open it in an office program,
or forward it to a model.

Current static checks include:

- file signature versus filename-extension validation;
- empty or unknown file rejection;
- PDF active-content markers such as JavaScript, launch, auto-open, and embedded
  file markers;
- archive entry-count, expansion-size, encryption, and path-traversal checks;
- Office macro-project detection inside Office archives;
- basic image metadata presence detection; and
- plaintext prompt-injection markers in the inspected byte range.

## Verdicts

| Verdict | Meaning | Required action |
|---|---|---|
| `allowed` | Static checks found no configured risky signal. | Use only through the target system's safe input path. |
| `quarantined` | A risky structure, active-content marker, macro, or instruction marker was found. | Keep it out of the model path until analyst review. |
| `blocked` | Empty, unsupported, unknown, or mismatched file type. | Reject the upload. |

An `allowed` verdict is not a malware guarantee. It means the file passed the
currently implemented, non-executing checks. OCR-based hidden-text detection,
full malware-engine scanning, content disarm and reconstruction, and isolated
dynamic analysis remain visible as partial or planned coverage in the AI System
coverage plan.

## Limits

Set these values in `.env` before starting the stack:

```dotenv
AEGISAI_MAX_REQUEST_BODY_BYTES=1048576
AEGISAI_MAX_FILE_SCAN_BYTES=1048576
```

Both defaults are 1 MiB. Keep these limits low in a public deployment and
perform heavyweight analysis in an isolated asynchronous worker, never in the
model-serving request path.

## API

Scan a harmless staging sample and optionally link it to an AI system profile:

```bash
curl --fail --request POST \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  -F "file=@./safe-test-document.pdf" \
  -F "system_id=PROFILE_ID" \
  http://127.0.0.1:8000/file-security/scans
```

View recent scans:

```bash
curl --fail \
  -H "Authorization: Bearer ${AEGISAI_ACCESS_TOKEN}" \
  http://127.0.0.1:8000/file-security/scans
```

Use only files that you are authorized to handle. Do not upload real malware or
customer files to a local development lab.
