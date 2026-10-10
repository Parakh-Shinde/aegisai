"""Bounded client for AEGISAI's isolated, no-egress OCR runner."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx

SUPPORTED_OCR_TYPES = frozenset({"jpeg", "png"})
MAX_EXTRACTED_TEXT_CHARACTERS = 32_768


class OCRRunnerError(RuntimeError):
    """Raised when a sandboxed extraction cannot produce trustworthy text."""


@dataclass(frozen=True)
class OCRExtraction:
    text: str
    sha256: str
    characters: int


def extract_text_in_sandbox(
    *,
    content: bytes,
    filename: str,
    detected_type: str,
    runner_url: str,
    runner_token: str | None,
    timeout_seconds: int,
    transport: httpx.BaseTransport | None = None,
) -> OCRExtraction:
    """Extract text through a fixed internal runner, never a request-provided URL."""
    if detected_type not in SUPPORTED_OCR_TYPES:
        raise OCRRunnerError("OCR is supported only for PNG and JPEG inputs.")
    if not runner_url:
        raise OCRRunnerError("The OCR sandbox is not configured.")

    headers = {
        "Content-Type": "application/octet-stream",
        "X-AEGISAI-Filename": filename,
        "X-AEGISAI-Detected-Type": detected_type,
    }
    if runner_token:
        headers["X-AEGISAI-OCR-Token"] = runner_token
    try:
        with httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            transport=transport,
        ) as client:
            response = client.post(
                f"{runner_url.rstrip('/')}/extract",
                content=content,
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OCRRunnerError("The OCR sandbox could not complete extraction.") from exc

    text = payload.get("text") if isinstance(payload, dict) else None
    if not isinstance(text, str):
        raise OCRRunnerError("The OCR sandbox returned an invalid response.")
    text = text[:MAX_EXTRACTED_TEXT_CHARACTERS]
    return OCRExtraction(
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        characters=len(text),
    )
