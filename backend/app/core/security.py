import hmac
import ipaddress
import os
import re
import socket
from urllib.parse import urlparse

from fastapi import Header, HTTPException, status

from app.core.config import get_settings

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


def require_agent_gateway_token(
    x_aegisai_agent_token: str | None = Header(default=None),
) -> None:
    """Authenticate an agent runtime at the pre-action enforcement boundary."""
    expected_token = get_settings().agent_gateway_token
    if not expected_token:
        # Local development only. Production configuration rejects a missing token.
        return
    if not x_aegisai_agent_token or not hmac.compare_digest(
        x_aegisai_agent_token,
        expected_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing agent gateway token.",
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

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"Invalid {field_name}: expected an http(s) URL.")

    hostname = parsed.hostname.lower()
    normalized_url = url.rstrip("/")
    local_hosts = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
    local_endpoints = {
        item.strip().rstrip("/")
        for item in os.getenv("AEGISAI_LOCAL_MODEL_ENDPOINTS", "").split(",")
        if item.strip()
    }

    if hostname in local_hosts or normalized_url in local_endpoints:
        return normalized_url

    if os.getenv("AEGISAI_ALLOW_REMOTE_OLLAMA") == "true":
        approved_endpoints = {
            item.strip().rstrip("/")
            for item in os.getenv("AEGISAI_APPROVED_MODEL_ENDPOINTS", "").split(",")
            if item.strip()
        }
        if normalized_url in approved_endpoints:
            _require_public_endpoint(hostname, field_name)
            return normalized_url
        raise ValueError(
            f"Invalid {field_name}: endpoint is not in the approved allowlist."
        )

    raise ValueError(
        f"Invalid {field_name}: remote model endpoints are disabled by default."
    )


def _require_public_endpoint(hostname: str, field_name: str) -> None:
    """Reject private/reserved addresses for remotely configured providers."""
    try:
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValueError(
            f"Invalid {field_name}: hostname could not be resolved."
        ) from exc

    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError(
            f"Invalid {field_name}: remote endpoints must resolve only to public "
            "IP addresses."
        )


def safe_upstream_error(message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=message,
    )
