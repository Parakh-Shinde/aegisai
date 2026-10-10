"""Minimal local-only OCR server for the AEGISAI internal sandbox network."""

from __future__ import annotations

import hmac
import json
import os
import subprocess
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_INPUT_BYTES = 1_048_576
MAX_TEXT_CHARACTERS = 32_768
OCR_TIMEOUT_SECONDS = 15
ALLOWED_TYPES = {"png": ".png", "jpeg": ".jpg"}


class Handler(BaseHTTPRequestHandler):
    server_version = "AEGISAI-OCR/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"detail": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/extract":
            self._json(HTTPStatus.NOT_FOUND, {"detail": "Not found."})
            return
        token = os.getenv("AEGISAI_OCR_RUNNER_TOKEN", "")
        supplied_token = self.headers.get("X-AEGISAI-OCR-Token", "")
        if token and not hmac.compare_digest(token, supplied_token):
            self._json(HTTPStatus.UNAUTHORIZED, {"detail": "Invalid runner token."})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"detail": "Content-Length required."})
            return
        if content_length < 1 or content_length > MAX_INPUT_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"detail": "Invalid input size."})
            return
        detected_type = self.headers.get("X-AEGISAI-Detected-Type", "")
        suffix = ALLOWED_TYPES.get(detected_type)
        if suffix is None:
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"detail": "Unsupported image type."})
            return
        content = self.rfile.read(content_length)
        if len(content) != content_length:
            self._json(HTTPStatus.BAD_REQUEST, {"detail": "Incomplete request body."})
            return
        self._extract(content, suffix)

    def _extract(self, content: bytes, suffix: str) -> None:
        try:
            with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
                input_path = Path(temp_dir) / f"input{suffix}"
                input_path.write_bytes(content)
                result = subprocess.run(
                    ["tesseract", str(input_path), "stdout", "--dpi", "300"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=OCR_TIMEOUT_SECONDS,
                    env={"PATH": os.getenv("PATH", ""), "HOME": "/tmp"},
                )
        except (OSError, subprocess.TimeoutExpired):
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"detail": "OCR unavailable."})
            return
        if result.returncode != 0:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": "OCR failed."})
            return
        self._json(HTTPStatus.OK, {"text": result.stdout[:MAX_TEXT_CHARACTERS]})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _json(self, status: HTTPStatus, payload: dict[str, str]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
