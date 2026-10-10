# Sandboxed OCR Security

AEGISAI can extract text from authorized PNG and JPEG uploads through an
optional OCR sandbox. The sandbox is designed for the local/controlled lab:

- It has no published host port.
- It belongs only to an internal Docker network shared with the API.
- It has a read-only filesystem, a small temporary filesystem, dropped Linux
  capabilities, `no-new-privileges`, CPU/memory/PID limits, and a subprocess
  timeout.
- It accepts a bounded raw request from AEGISAI only and does not fetch URLs,
  render documents, call tools, or execute upload content.
- The original file is kept only in the sandbox temporary filesystem for the
  extraction request and is deleted when that request finishes.

The extracted text is sent through AEGISAI's existing RAG-source policy checks.
If it contains instruction override, secret-extraction, tool-action, role
impersonation, or invisible-text signals, the upload is quarantined. Extracted
text evidence is protected by AEGISAI's configured evidence encryption key.

## Enable locally

Add these values to `.env`. Use a unique token of at least 32 characters.

```dotenv
AEGISAI_OCR_ENABLED=true
AEGISAI_OCR_RUNNER_TOKEN=replace-with-a-long-random-local-token
AEGISAI_OCR_TIMEOUT_SECONDS=20
```

Then start the normal stack and the separate OCR profile:

```bash
make restart
make ocr-start
docker compose ps
```

`ocr-runner` should be running, but it will not expose any port on Windows or
WSL. If OCR is disabled, unavailable, or a static scan has already flagged the
file, AEGISAI returns a quarantined result and does not send the input to OCR.

## Run an OCR security scan

Use a harmless image that you own. This example uses an existing PNG only as a
controlled local test:

```bash
curl --fail -F "file=@/path/to/your-test-image.png;type=image/png" \
  http://127.0.0.1:8000/file-security/ocr | jq
```

The response includes the scan ID, extraction status, extracted-text digest and
length, policy signals, and the extracted evidence for an authorized analyst.
You can retrieve the same evidence later:

```bash
curl --fail http://127.0.0.1:8000/file-security/scans/SCAN_ID/ocr | jq
```

## Scope and limitation

OCR output is evidence, not proof that an image is benign. OCR can miss text,
misread text, or fail on visual obfuscation. AEGISAI therefore fails closed for
an unavailable sandbox and keeps flagged OCR text out of automatic model and
RAG paths. Test only authorized staging or fake data; do not use this local lab
to process production-sensitive files.
