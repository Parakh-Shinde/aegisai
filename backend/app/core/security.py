import hmac
import os
import re
from urllib.parse import urlparse

from fastapi import Header, HTTPException, status

API_KEY_ENV = "AEGISAI_API_KEY"
MAX_MODEL_NAME_LENGTH = 100
MAX_PROMPT_LENGTH = 4000
MAX_REVIEW_NOTES_LENGTH = 1000
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected_api_key = os.getenv(API_KEY_ENV)

    if not expected_api_key:
        return

    if not x_api_key or not hmac.compare_digest(x_api_key, expected_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


def validate_identifier(value: str, field_name: str) -> str:
    if not SAFE_IDENTIFIER_PATTERN.fullmatch(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid {field_name}. Use 1-128 letters, numbers, dots, "
                "colons, underscores, or hyphens."
            ),
        )

    return value


def validate_local_http_url(url: str, field_name: str = "url") -> str:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid {field_name}: expected an http(s) URL.")

    hostname = parsed.hostname.lower()
    allowed_hosts = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}

    if hostname in allowed_hosts or hostname.startswith("172."):
        return url.rstrip("/")

    if os.getenv("AEGISAI_ALLOW_REMOTE_OLLAMA") == "true":
        return url.rstrip("/")

    raise ValueError(
        f"Invalid {field_name}: remote model endpoints are disabled by default."
    )


def safe_upstream_error(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=message,
    )
